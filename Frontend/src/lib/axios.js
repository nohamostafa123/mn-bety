import axios from "axios";
import { store } from "../store/store.js";
import { clearAuth, setAccessToken } from "../Auth/Features/authSlice";
import { showVerificationToast } from "./toast";
import { resendVerificationThunk } from "../Auth/Features/authThunks";

const BASE_URL = "https://mn-bety-server-production-c3d7.up.railway.app/api";

// ============================================================
//         1. PUBLIC INSTANCE — login, register, refresh
//    No interceptors — no token check, no auto refresh
// ============================================================
export const publicAxios = axios.create({
  baseURL: BASE_URL,
  withCredentials: true, // needed for refresh token cookie
});

// ============================================================
//         2. PRIVATE INSTANCE — all protected routes
//    Attaches token + handles silent refresh on 401
// ============================================================
export const privateAxios = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

// ============================================================
//              SHARED FUNCTIONS
// ============================================================

/**
 * @desc  Request a new access token using the refresh token cookie
 * @returns {string} new access token
 */
export const refreshTokenRequest = async () => {
  const res = await publicAxios.post("/auth/refresh-token");
  return res.data.data; // new access token string
};

/**
 * @desc  Clear auth state — call on logout or when refresh fails
 */
export const logoutRequest = () => {
  store.dispatch(clearAuth());
};

// ============================================================
//              PRIVATE INSTANCE INTERCEPTORS
// ============================================================

// ─── Attach access token to every private request ────────────────────────────
privateAxios.interceptors.request.use((config) => {
  const token = store.getState().auth.accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ─── Handle responses ────────────────────────────────────────────────────────
privateAxios.interceptors.response.use(
  (response) => response,

  async (error) => {
    const originalRequest = error.config;
    const status = error.response?.status;
    const message = error.response?.data?.message || "";

    // ─── 401: silent token refresh ─────────────────────────────────────────
    if (status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const newToken = await refreshTokenRequest();
        store.dispatch(setAccessToken(newToken));
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return privateAxios(originalRequest);
      } catch {
        logoutRequest();
        return Promise.reject(error);
      }
    }

    // ─── 403: Email not verified ────────────────────────────────────────────
    // Backend message: "Please verify your email address to access this feature."
    if (
      status === 403 &&
      message === "Please verify your email address to access this feature."
    ) {
      showVerificationToast({
        onResend: async () => {
          const result = await store.dispatch(resendVerificationThunk());
          if (resendVerificationThunk.fulfilled.match(result)) {
            return {
              success: true,
              message: "تم إرسال رابط التحقق! راجع صندوق الوارد.",
            };
          }

          const errMsg = result.payload || "";
          const isCooldown =
            errMsg.includes("Please wait") ||
            errMsg.includes("wait before") ||
            errMsg.includes("recently sent");

          return {
            success: false,
            message: isCooldown
              ? "يرجى الانتظار دقيقة قبل طلب رابط جديد."
              : errMsg || "حدث خطأ أثناء الإرسال.",
          };
        },
      });

      return Promise.resolve({ data: null, _handled: true });
      // Don't show another error toast — verification toast handles everything
      // return Promise.reject(error);
    }

    // ─── All other errors — let the calling component handle them ──────────
    return Promise.reject(error);
  }
);
