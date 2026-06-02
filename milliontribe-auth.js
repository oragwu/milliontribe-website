// ============================================================
// MILLION TRIBE — Authentication Module
// Handles signup, login, logout, password reset
// Uses Supabase Auth — free, secure, scalable
// ============================================================

const MTAuth = (() => {

  const SUPABASE_URL = window.MT_SUPABASE_URL || 'https://mkcrexrulbwyyewvkmqj.supabase.co';
  const SUPABASE_KEY = window.MT_SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1rY3JleHJ1bGJ3eXlld3ZrbXFqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkzODEyNzAsImV4cCI6MjA5NDk1NzI3MH0.UvAe1GHSS_JNusJ2AICOoQCVb-Xf2J4k-3Si3-9IrrE';

  const headers = {
    'Content-Type': 'application/json',
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
  };

  // ── SIGN UP ──
  const signUp = async (email, password, username, displayName, referralCode = null) => {
    try {
      // 1. Create auth user
      const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.msg || data.error_description || 'Signup failed');

      const userId = data.user?.id;
      if (!userId) throw new Error('No user ID returned');

      // 2. Create profile
      const refCode = 'MT' + Math.random().toString(36).substr(2, 8).toUpperCase();
      await fetch(`${SUPABASE_URL}/rest/v1/profiles`, {
        method: 'POST',
        headers: { ...headers, 'Prefer': 'return=minimal' },
        body: JSON.stringify({
          id: userId,
          username: username.toLowerCase().replace(/[^a-z0-9_]/g, ''),
          display_name: displayName,
          referral_code: refCode,
          referred_by: referralCode || null,
          tribe_balance: 225,
          tribe_earned_total: 225,
          subscription_status: 'waitlist',
        })
      });

      // 3. Log welcome TRIBE transaction
      await fetch(`${SUPABASE_URL}/rest/v1/tribe_transactions`, {
        method: 'POST',
        headers: { ...headers, 'Prefer': 'return=minimal' },
        body: JSON.stringify({
          user_id: userId,
          type: 'welcome_bonus',
          amount: 225,
          balance_after: 225,
          description: 'Welcome bonus — founding member'
        })
      });

      return { success: true, user: data.user, session: data.session };
    } catch(e) {
      return { success: false, error: e.message };
    }
  };

  // ── SIGN IN ──
  const signIn = async (email, password) => {
    try {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error_description || 'Login failed');

      // Store session
      localStorage.setItem('mt_session', JSON.stringify({
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: Date.now() + (data.expires_in * 1000),
        user: data.user
      }));

      // Update last seen
      if (data.user?.id) {
        await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${data.user.id}`, {
          method: 'PATCH',
          headers: { ...headers, 'Prefer': 'return=minimal' },
          body: JSON.stringify({ last_seen: new Date().toISOString() })
        });
      }

      return { success: true, user: data.user, session: data };
    } catch(e) {
      return { success: false, error: e.message };
    }
  };

  // ── SIGN OUT ──
  const signOut = async () => {
    try {
      const session = getSession();
      if (session?.access_token) {
        await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
          method: 'POST',
          headers: { ...headers, 'Authorization': `Bearer ${session.access_token}` }
        });
      }
      localStorage.removeItem('mt_session');
      return { success: true };
    } catch(e) {
      localStorage.removeItem('mt_session');
      return { success: true };
    }
  };

  // ── PASSWORD RESET ──
  const resetPassword = async (email) => {
    try {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/recover`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email })
      });
      return { success: res.ok };
    } catch(e) {
      return { success: false, error: e.message };
    }
  };

  // ── GET SESSION ──
  const getSession = () => {
    try {
      const raw = localStorage.getItem('mt_session');
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (session.expires_at < Date.now()) {
        localStorage.removeItem('mt_session');
        return null;
      }
      return session;
    } catch(e) { return null; }
  };

  // ── IS LOGGED IN ──
  const isLoggedIn = () => getSession() !== null;

  // ── GET CURRENT USER ──
  const getCurrentUser = () => getSession()?.user || null;

  // ── GET AUTH HEADERS ──
  const authHeaders = () => {
    const session = getSession();
    return {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${session?.access_token || SUPABASE_KEY}`,
    };
  };

  // ── REFRESH SESSION ──
  const refreshSession = async () => {
    try {
      const session = getSession();
      if (!session?.refresh_token) return null;
      const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ refresh_token: session.refresh_token })
      });
      const data = await res.json();
      if (res.ok) {
        localStorage.setItem('mt_session', JSON.stringify({
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          expires_at: Date.now() + (data.expires_in * 1000),
          user: data.user
        }));
        return data;
      }
      return null;
    } catch(e) { return null; }
  };

  // ── GOOGLE OAUTH ──
  const signInWithGoogle = async () => {
    window.location.href = `${SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to=${window.location.origin}/platform/callback`;
  };

  return { signUp, signIn, signOut, resetPassword, getSession, isLoggedIn, getCurrentUser, authHeaders, refreshSession, signInWithGoogle };

})();

window.MTAuth = MTAuth;