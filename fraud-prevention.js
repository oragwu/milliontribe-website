// ============================================================
// MILLION TRIBE — Fraud Prevention Module
// Include this script on waitlist.html and all signup pages
//
// HOW TO USE:
// 1. Add to waitlist.html: <script src="fraud-prevention.js"></script>
// 2. Call before signup: const check = await FraudPrevention.checkRegistration(name, email, phone)
// 3. If check.blocked === true — stop signup and show error
// 4. If check.riskLevel === 'high' — flag for manual review
// ============================================================

const FraudPrevention = (() => {

  const SUPABASE_URL = window.SUPABASE_URL || 'YOUR_SUPABASE_URL';
  const SUPABASE_KEY = window.SUPABASE_KEY || 'YOUR_SUPABASE_ANON_KEY';

  // ══════════════════════════════════════
  // 1. DEVICE FINGERPRINTING
  // Builds a unique hash from browser/device characteristics
  // Free — no external API needed
  // ══════════════════════════════════════
  const getDeviceFingerprint = async () => {
    const components = [
      navigator.userAgent,
      navigator.language,
      navigator.platform,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || 'unknown',
      navigator.deviceMemory || 'unknown',
      // Canvas fingerprint
      await getCanvasFingerprint(),
      // WebGL fingerprint
      getWebGLFingerprint(),
      // Installed fonts proxy
      navigator.plugins ? navigator.plugins.length : 0,
    ];

    const raw = components.join('|||');
    return await hashString(raw);
  };

  const getCanvasFingerprint = async () => {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('MillionTribe🏆', 2, 2);
      return canvas.toDataURL().slice(-50);
    } catch(e) { return 'canvas_blocked'; }
  };

  const getWebGLFingerprint = () => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl_none';
      const renderer = gl.getParameter(gl.RENDERER);
      const vendor = gl.getParameter(gl.VENDOR);
      return `${vendor}::${renderer}`;
    } catch(e) { return 'webgl_blocked'; }
  };

  const hashString = async (str) => {
    const msgBuffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // ══════════════════════════════════════
  // 2. IP DETECTION
  // Free tier — ipapi.co (1,000 requests/day free)
  // ══════════════════════════════════════
  const getIPInfo = async () => {
    try {
      const response = await fetch('https://ipapi.co/json/', { mode: 'cors' });
      if (!response.ok) return null;
      const data = await response.json();
      return {
        ip:          data.ip,
        country:     data.country_name,
        region:      data.region,
        city:        data.city,
        org:         data.org,
        // Detect datacenters/VPNs by ASN
        isDatacenter: data.org && (
          data.org.includes('Amazon') ||
          data.org.includes('Google') ||
          data.org.includes('Microsoft') ||
          data.org.includes('DigitalOcean') ||
          data.org.includes('Linode') ||
          data.org.includes('Vultr') ||
          data.org.includes('Cloudflare') ||
          data.org.includes('NordVPN') ||
          data.org.includes('ExpressVPN') ||
          data.org.includes('Mullvad')
        ),
      };
    } catch(e) {
      console.log('IP check failed:', e.message);
      return null;
    }
  };

  // ══════════════════════════════════════
  // 3. NAME NORMALIZATION
  // For fuzzy matching — removes spaces, punctuation, lowercases
  // ══════════════════════════════════════
  const normalizeName = (name) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .trim();
  };

  // Similarity score between two strings (0-1)
  // Uses Levenshtein distance
  const nameSimilarity = (a, b) => {
    const s1 = normalizeName(a);
    const s2 = normalizeName(b);
    if (s1 === s2) return 1.0;
    const longer = s1.length > s2.length ? s1 : s2;
    const shorter = s1.length > s2.length ? s2 : s1;
    if (longer.length === 0) return 1.0;
    return (longer.length - editDistance(longer, shorter)) / longer.length;
  };

  const editDistance = (s1, s2) => {
    const costs = [];
    for (let i = 0; i <= s1.length; i++) {
      let lastValue = i;
      for (let j = 0; j <= s2.length; j++) {
        if (i === 0) { costs[j] = j; }
        else if (j > 0) {
          let newValue = costs[j - 1];
          if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
          }
          costs[j - 1] = lastValue;
          lastValue = newValue;
        }
      }
      if (i > 0) costs[s2.length] = lastValue;
    }
    return costs[s2.length];
  };

  // ══════════════════════════════════════
  // 4. SUPABASE FRAUD CHECK
  // Calls the fraud_check_registration database function
  // ══════════════════════════════════════
  const runDatabaseFraudCheck = async (email, name, deviceFingerprint, ipAddress, phone) => {
    try {
      const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/fraud_check_registration`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
        },
        body: JSON.stringify({
          p_email: email,
          p_name: name,
          p_device_fingerprint: deviceFingerprint,
          p_ip_address: ipAddress,
          p_phone: phone || null,
        })
      });
      if (!response.ok) return null;
      return await response.json();
    } catch(e) {
      console.log('Database fraud check failed:', e.message);
      return null;
    }
  };

  // ══════════════════════════════════════
  // 5. LOG DEVICE FINGERPRINT
  // Saves device info to Supabase for future checks
  // ══════════════════════════════════════
  const logDeviceFingerprint = async (fingerprintHash, email, ipInfo) => {
    try {
      await fetch(`${SUPABASE_URL}/rest/v1/device_fingerprints`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Prefer': 'resolution=merge-duplicates',
        },
        body: JSON.stringify({
          fingerprint_hash:   fingerprintHash,
          email:              email,
          ip_address:         ipInfo?.ip,
          user_agent:         navigator.userAgent,
          screen_resolution:  `${screen.width}x${screen.height}`,
          timezone:           Intl.DateTimeFormat().resolvedOptions().timeZone,
          language:           navigator.language,
          platform:           navigator.platform,
          vpn_detected:       ipInfo?.isDatacenter || false,
          last_seen:          new Date().toISOString(),
        })
      });
    } catch(e) {
      console.log('Device log failed:', e.message);
    }
  };

  // ══════════════════════════════════════
  // 6. LOG IP
  // ══════════════════════════════════════
  const logIP = async (email, ipInfo) => {
    if (!ipInfo) return;
    try {
      await fetch(`${SUPABASE_URL}/rest/v1/ip_logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify({
          ip_address:    ipInfo.ip,
          email:         email,
          country:       ipInfo.country,
          region:        ipInfo.region,
          city:          ipInfo.city,
          is_datacenter: ipInfo.isDatacenter || false,
          risk_score:    ipInfo.isDatacenter ? 60 : 0,
          action_taken:  ipInfo.isDatacenter ? 'flagged' : 'allowed',
        })
      });
    } catch(e) {
      console.log('IP log failed:', e.message);
    }
  };

  // ══════════════════════════════════════
  // 7. LOG VERIFICATION RESULT
  // ══════════════════════════════════════
  const logVerification = async (email, dbResult, deviceFingerprint, ipInfo, outcome) => {
    try {
      await fetch(`${SUPABASE_URL}/rest/v1/verification_logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify({
          email:               email,
          check_type:          'registration',
          device_match:        dbResult?.flags?.includes('DEVICE_MATCHES_WINNER') || false,
          ip_flagged:          ipInfo?.isDatacenter || false,
          winner_registry_hit: dbResult?.flags?.includes('EMAIL_MATCHES_WINNER') || false,
          overall_risk:        dbResult?.risk_level || 'low',
          outcome:             outcome,
          outcome_reason:      dbResult?.flags?.join(', ') || 'clean',
        })
      });
    } catch(e) {
      console.log('Verification log failed:', e.message);
    }
  };

  // ══════════════════════════════════════
  // 8. MAIN CHECK FUNCTION
  // Call this before every registration
  // ══════════════════════════════════════
  const checkRegistration = async (name, email, phone = null) => {
    console.log('🔐 Running fraud prevention check...');

    const result = {
      blocked:     false,
      riskLevel:   'low',
      flags:       [],
      deviceHash:  null,
      ipInfo:      null,
      message:     'Registration approved',
    };

    try {
      // Step 1 — Get device fingerprint
      const deviceHash = await getDeviceFingerprint();
      result.deviceHash = deviceHash;
      console.log('Device fingerprint:', deviceHash.slice(0, 12) + '...');

      // Step 2 — Get IP info
      const ipInfo = await getIPInfo();
      result.ipInfo = ipInfo;
      if (ipInfo?.isDatacenter) {
        result.flags.push('VPN_OR_DATACENTER_DETECTED');
        result.riskLevel = 'medium';
        console.log('⚠️ VPN/datacenter IP detected:', ipInfo.org);
      }

      // Step 3 — Run database fraud check
      const dbResult = await runDatabaseFraudCheck(
        email, name, deviceHash, ipInfo?.ip, phone
      );

      if (dbResult) {
        if (dbResult.blocked) {
          result.blocked = true;
          result.riskLevel = 'critical';
          result.message = 'Registration blocked — identity matches a previous winner';
          result.flags = [...result.flags, ...(dbResult.flags || [])];
          console.log('🚨 BLOCKED:', dbResult.flags);
        } else if (dbResult.risk_level === 'high') {
          result.riskLevel = 'high';
          result.flags = [...result.flags, ...(dbResult.flags || [])];
          console.log('⚠️ HIGH RISK:', dbResult.flags);
        } else if (dbResult.risk_level === 'medium') {
          if (result.riskLevel === 'low') result.riskLevel = 'medium';
          result.flags = [...result.flags, ...(dbResult.flags || [])];
        }
      }

      // Step 4 — Log everything
      await Promise.all([
        logDeviceFingerprint(deviceHash, email, ipInfo),
        logIP(email, ipInfo),
        logVerification(email, dbResult, deviceHash, ipInfo,
          result.blocked ? 'blocked' : result.riskLevel === 'high' ? 'flagged' : 'approved'
        ),
      ]);

      console.log(`✅ Fraud check complete — Risk: ${result.riskLevel}`);

    } catch(e) {
      // Never block signup due to fraud check error
      // Log silently and allow through
      console.log('Fraud check error (allowing through):', e.message);
    }

    return result;
  };

  // ══════════════════════════════════════
  // PUBLIC API
  // ══════════════════════════════════════
  return {
    checkRegistration,
    getDeviceFingerprint,
    normalizeName,
    nameSimilarity,
  };

})();

// Make available globally
window.FraudPrevention = FraudPrevention;