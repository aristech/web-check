import axios from 'axios';
import middleware from './_common/middleware.js';

// Common WordPress plugins to scan
const COMMON_PLUGINS = [
  'akismet', 'contact-form-7', 'yoast-seo', 'woocommerce', 'elementor',
  'wordfence', 'jetpack', 'classic-editor', 'wpforms-lite', 'all-in-one-seo-pack',
  'updraftplus', 'wp-super-cache', 'really-simple-ssl', 'duplicate-post',
  'limit-login-attempts-reloaded', 'wp-mail-smtp', 'advanced-custom-fields',
  'redirection', 'sucuri-scanner', 'all-in-one-wp-migration', 'ninja-forms',
  'tablepress', 'cookie-notice', 'autoptimize', 'ewww-image-optimizer',
  'loginizer', 'wp-optimize', 'slider-revolution', 'query-monitor', 'health-check'
];

// Known critical vulnerabilities (CVE database subset - high/critical from last 2 years)
const KNOWN_VULNERABILITIES = {
  wordpress: {
    '6.0': [],
    '6.1': [],
    '6.2': [],
    '6.3': [],
    '6.4': [],
    '6.5': [],
    '6.6': [],
    '6.7': [],
    '5.9': [{ id: 'CVE-2022-21661', severity: 'high', description: 'SQL Injection in WP_Query' }],
    '5.8': [{ id: 'CVE-2022-21661', severity: 'high', description: 'SQL Injection in WP_Query' }],
    '5.7': [{ id: 'CVE-2022-21661', severity: 'high', description: 'SQL Injection in WP_Query' }],
  },
  plugins: {
    'elementor': {
      '<3.12.0': [{ id: 'CVE-2023-32243', severity: 'critical', description: 'Authenticated RCE' }],
    },
    'contact-form-7': {
      '<5.8.4': [{ id: 'CVE-2023-6449', severity: 'high', description: 'Arbitrary File Upload' }],
    },
    'woocommerce': {
      '<8.6.0': [{ id: 'CVE-2024-22147', severity: 'high', description: 'SQL Injection' }],
    },
    'slider-revolution': {
      '<6.6.15': [{ id: 'CVE-2023-4596', severity: 'critical', description: 'Unauthenticated RCE' }],
    },
    'all-in-one-seo-pack': {
      '<4.3.0': [{ id: 'CVE-2023-0586', severity: 'high', description: 'Privilege Escalation' }],
    },
    'advanced-custom-fields': {
      '<6.1.6': [{ id: 'CVE-2023-30777', severity: 'high', description: 'Reflected XSS' }],
    },
    'updraftplus': {
      '<1.23.3': [{ id: 'CVE-2023-32960', severity: 'high', description: 'Path Traversal' }],
    },
    'jetpack': {
      '<12.1.1': [{ id: 'CVE-2023-28121', severity: 'critical', description: 'Auth Bypass' }],
    },
    'ninja-forms': {
      '<3.6.26': [{ id: 'CVE-2023-37979', severity: 'critical', description: 'Unauthenticated XSS' }],
    },
    'loginizer': {
      '<1.7.9': [{ id: 'CVE-2023-5360', severity: 'critical', description: 'SQL Injection' }],
    },
  }
};

// Axios config for requests
const axiosConfig = {
  timeout: 8000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  },
  validateStatus: () => true,
  maxRedirects: 3,
};

// Extract WordPress version from various sources
const extractVersion = (html, headers) => {
  // From generator meta tag
  const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)["']/i);
  if (generatorMatch) return { version: generatorMatch[1], source: 'generator-meta' };

  // From wp-emoji script
  const emojiMatch = html.match(/wp-emoji-release\.min\.js\?ver=([\d.]+)/);
  if (emojiMatch) return { version: emojiMatch[1], source: 'wp-emoji' };

  // From stylesheet versions
  const styleMatch = html.match(/\?ver=([\d.]+)/);
  if (styleMatch) return { version: styleMatch[1], source: 'asset-version' };

  return { version: null, source: 'unknown' };
};

// Extract theme from HTML
const extractTheme = (html) => {
  const themeMatch = html.match(/\/wp-content\/themes\/([^\/'"]+)/);
  return themeMatch ? themeMatch[1] : null;
};

// Check if version is vulnerable
const checkVersionVulnerabilities = (type, name, version) => {
  if (!version) return [];

  const db = type === 'wordpress' ? KNOWN_VULNERABILITIES.wordpress : KNOWN_VULNERABILITIES.plugins[name];
  if (!db) return [];

  const vulns = [];
  for (const [versionRange, cves] of Object.entries(db)) {
    if (versionRange.startsWith('<')) {
      const maxVer = versionRange.slice(1);
      if (compareVersions(version, maxVer) < 0) {
        vulns.push(...cves);
      }
    } else if (version === versionRange) {
      vulns.push(...cves);
    }
  }
  return vulns;
};

// Simple version comparison
const compareVersions = (v1, v2) => {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    if (p1 < p2) return -1;
    if (p1 > p2) return 1;
  }
  return 0;
};

// WordPress detection
const detectWordPress = async (url, html) => {
  const indicators = {
    wpContent: html.includes('/wp-content/'),
    wpIncludes: html.includes('/wp-includes/'),
    generatorMeta: /WordPress/i.test(html),
    wpEmoji: html.includes('wp-emoji'),
    wpJson: html.includes('/wp-json/'),
  };

  const detectionScore = Object.values(indicators).filter(Boolean).length;
  return {
    isWordPress: detectionScore >= 2,
    indicators,
    confidence: Math.min(100, detectionScore * 25),
  };
};

// Check sensitive files
const checkSensitiveFiles = async (baseUrl) => {
  const files = [
    { path: '/wp-config.php', name: 'wp-config.php', critical: true },
    { path: '/wp-config.php.bak', name: 'wp-config.php.bak', critical: true },
    { path: '/wp-config.php~', name: 'wp-config.php~', critical: true },
    { path: '/wp-config.php.old', name: 'wp-config.php.old', critical: true },
    { path: '/wp-config.php.save', name: 'wp-config.php.save', critical: true },
    { path: '/.htaccess', name: '.htaccess', critical: false },
    { path: '/wp-content/debug.log', name: 'debug.log', critical: true },
    { path: '/error_log', name: 'error_log', critical: false },
    { path: '/readme.html', name: 'readme.html', critical: false },
    { path: '/license.txt', name: 'license.txt', critical: false },
    { path: '/wp-config-sample.php', name: 'wp-config-sample.php', critical: false },
  ];

  const results = await Promise.allSettled(
    files.map(async (file) => {
      try {
        const response = await axios.head(`${baseUrl}${file.path}`, { ...axiosConfig, timeout: 5000 });
        return {
          ...file,
          exposed: response.status === 200,
          status: response.status,
        };
      } catch {
        return { ...file, exposed: false, status: 0 };
      }
    })
  );

  return results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value)
    .filter(f => f.exposed);
};

// Check XML-RPC
const checkXmlRpc = async (baseUrl) => {
  try {
    const response = await axios.post(
      `${baseUrl}/xmlrpc.php`,
      '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
      {
        ...axiosConfig,
        headers: { ...axiosConfig.headers, 'Content-Type': 'text/xml' },
      }
    );

    if (response.status === 200 && response.data.includes('methodResponse')) {
      const methods = response.data.match(/<string>([^<]+)<\/string>/g) || [];
      const methodList = methods.map(m => m.replace(/<\/?string>/g, ''));
      return {
        enabled: true,
        methods: methodList.slice(0, 20), // Limit to 20 methods
        pingbackEnabled: methodList.includes('pingback.ping'),
        totalMethods: methodList.length,
      };
    }
    return { enabled: false, methods: [], pingbackEnabled: false };
  } catch {
    return { enabled: false, methods: [], pingbackEnabled: false };
  }
};

// Check user enumeration
const checkUserEnumeration = async (baseUrl) => {
  const results = {
    restApiExposed: false,
    authorArchivesEnabled: false,
    usersFound: [],
  };

  // Check REST API users endpoint
  try {
    const response = await axios.get(`${baseUrl}/wp-json/wp/v2/users`, axiosConfig);
    if (response.status === 200 && Array.isArray(response.data)) {
      results.restApiExposed = true;
      results.usersFound = response.data.slice(0, 10).map(u => ({
        id: u.id,
        name: u.name,
        slug: u.slug,
      }));
    }
  } catch {}

  // Check author archives
  try {
    const response = await axios.get(`${baseUrl}/?author=1`, { ...axiosConfig, maxRedirects: 0 });
    if (response.status === 301 || response.status === 302) {
      const location = response.headers.location || '';
      if (location.includes('/author/')) {
        results.authorArchivesEnabled = true;
      }
    }
  } catch {}

  return results;
};

// Check directory listing
const checkDirectoryListing = async (baseUrl) => {
  const directories = [
    '/wp-content/uploads/',
    '/wp-content/plugins/',
    '/wp-content/themes/',
    '/wp-includes/',
  ];

  const exposed = [];
  await Promise.allSettled(
    directories.map(async (dir) => {
      try {
        const response = await axios.get(`${baseUrl}${dir}`, { ...axiosConfig, timeout: 5000 });
        if (response.status === 200 && response.data.includes('Index of')) {
          exposed.push(dir);
        }
      } catch {}
    })
  );

  return exposed;
};

// Check REST API
const checkRestApi = async (baseUrl) => {
  try {
    const response = await axios.get(`${baseUrl}/wp-json/`, axiosConfig);
    if (response.status === 200 && response.data.namespaces) {
      return {
        exposed: true,
        namespaces: response.data.namespaces.slice(0, 15),
        name: response.data.name,
        description: response.data.description,
      };
    }
    return { exposed: false, namespaces: [] };
  } catch {
    return { exposed: false, namespaces: [] };
  }
};

// Check plugins
const checkPlugins = async (baseUrl, html) => {
  const detectedPlugins = [];

  // Extract plugins from HTML
  const pluginMatches = html.matchAll(/\/wp-content\/plugins\/([^\/'"]+)/g);
  const htmlPlugins = [...new Set([...pluginMatches].map(m => m[1]))];

  // Combine with common plugins
  const pluginsToCheck = [...new Set([...htmlPlugins, ...COMMON_PLUGINS])];

  // Check plugins in batches
  const batchSize = 10;
  for (let i = 0; i < Math.min(pluginsToCheck.length, 30); i += batchSize) {
    const batch = pluginsToCheck.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map(async (slug) => {
        try {
          const response = await axios.get(
            `${baseUrl}/wp-content/plugins/${slug}/readme.txt`,
            { ...axiosConfig, timeout: 5000 }
          );
          if (response.status === 200) {
            // Extract version from readme
            const versionMatch = response.data.match(/Stable tag:\s*([\d.]+)/i);
            const nameMatch = response.data.match(/===\s*(.+?)\s*===/);
            return {
              slug,
              name: nameMatch ? nameMatch[1] : slug,
              version: versionMatch ? versionMatch[1] : null,
              detected: true,
            };
          }
          return null;
        } catch {
          return null;
        }
      })
    );

    results.forEach(r => {
      if (r.status === 'fulfilled' && r.value) {
        const plugin = r.value;
        plugin.vulnerabilities = checkVersionVulnerabilities('plugin', plugin.slug, plugin.version);
        detectedPlugins.push(plugin);
      }
    });
  }

  // Also add plugins found in HTML that weren't verified via readme
  htmlPlugins.forEach(slug => {
    if (!detectedPlugins.find(p => p.slug === slug)) {
      detectedPlugins.push({
        slug,
        name: slug,
        version: null,
        detected: true,
        source: 'html',
        vulnerabilities: [],
      });
    }
  });

  return detectedPlugins;
};

// Check theme
const checkTheme = async (baseUrl, themeName) => {
  if (!themeName) return null;

  try {
    const response = await axios.get(
      `${baseUrl}/wp-content/themes/${themeName}/style.css`,
      axiosConfig
    );
    if (response.status === 200) {
      const versionMatch = response.data.match(/Version:\s*([\d.]+)/i);
      const nameMatch = response.data.match(/Theme Name:\s*(.+)/i);
      return {
        slug: themeName,
        name: nameMatch ? nameMatch[1].trim() : themeName,
        version: versionMatch ? versionMatch[1] : null,
      };
    }
  } catch {}

  return { slug: themeName, name: themeName, version: null };
};

// Calculate security score
const calculateSecurityScore = (results) => {
  let score = 100;
  const deductions = [];

  // Version issues (-20 max)
  if (results.version.vulnerabilities?.length > 0) {
    score -= 20;
    deductions.push('Outdated WordPress with known vulnerabilities');
  }

  // Exposed files (-25 max)
  const criticalFiles = results.exposedFiles.filter(f => f.critical);
  if (criticalFiles.length > 0) {
    score -= Math.min(25, criticalFiles.length * 10);
    deductions.push('Critical files exposed');
  }

  // XML-RPC enabled (-10)
  if (results.xmlRpc.enabled) {
    score -= 10;
    if (results.xmlRpc.pingbackEnabled) score -= 5;
    deductions.push('XML-RPC enabled');
  }

  // User enumeration (-15 max)
  if (results.userEnumeration.restApiExposed) {
    score -= 10;
    deductions.push('User data exposed via REST API');
  }
  if (results.userEnumeration.authorArchivesEnabled) {
    score -= 5;
    deductions.push('Author archives enabled');
  }

  // Directory listing (-10 max)
  if (results.directoryListing.length > 0) {
    score -= Math.min(10, results.directoryListing.length * 3);
    deductions.push('Directory listing enabled');
  }

  // Plugin vulnerabilities (-20 max)
  const vulnPlugins = results.plugins.filter(p => p.vulnerabilities?.length > 0);
  if (vulnPlugins.length > 0) {
    score -= Math.min(20, vulnPlugins.length * 5);
    deductions.push('Plugins with known vulnerabilities');
  }

  return { score: Math.max(0, score), deductions };
};

// Generate recommendations
const generateRecommendations = (results) => {
  const recommendations = [];

  if (results.version.vulnerabilities?.length > 0) {
    recommendations.push({
      severity: 'critical',
      title: 'Update WordPress Core',
      description: `WordPress ${results.version.detected} has known vulnerabilities. Update to the latest version immediately.`,
    });
  }

  const criticalFiles = results.exposedFiles.filter(f => f.critical);
  if (criticalFiles.length > 0) {
    recommendations.push({
      severity: 'critical',
      title: 'Protect Sensitive Files',
      description: `Critical files are publicly accessible: ${criticalFiles.map(f => f.name).join(', ')}. Configure server to block access.`,
    });
  }

  if (results.xmlRpc.enabled) {
    recommendations.push({
      severity: 'high',
      title: 'Disable XML-RPC',
      description: 'XML-RPC is enabled and can be used for brute force attacks. Disable it if not needed.',
    });
  }

  if (results.userEnumeration.restApiExposed) {
    recommendations.push({
      severity: 'high',
      title: 'Restrict User API',
      description: 'User information is exposed via REST API. Restrict access to authenticated users only.',
    });
  }

  if (results.directoryListing.length > 0) {
    recommendations.push({
      severity: 'medium',
      title: 'Disable Directory Listing',
      description: `Directory listing is enabled for: ${results.directoryListing.join(', ')}. Add "Options -Indexes" to .htaccess.`,
    });
  }

  const vulnPlugins = results.plugins.filter(p => p.vulnerabilities?.length > 0);
  vulnPlugins.forEach(plugin => {
    recommendations.push({
      severity: 'critical',
      title: `Update ${plugin.name}`,
      description: `Plugin "${plugin.name}" v${plugin.version} has known vulnerabilities: ${plugin.vulnerabilities.map(v => v.id).join(', ')}`,
    });
  });

  if (results.exposedFiles.find(f => f.name === 'readme.html')) {
    recommendations.push({
      severity: 'low',
      title: 'Remove readme.html',
      description: 'The readme.html file reveals WordPress version. Delete it from the server.',
    });
  }

  return recommendations.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });
};

// Main handler
const wordpressSecurityHandler = async (url) => {
  const baseUrl = url.replace(/\/$/, '');

  try {
    // Fetch main page
    const response = await axios.get(baseUrl, axiosConfig);
    const html = response.data;

    // Detect WordPress
    const detection = await detectWordPress(baseUrl, html);
    if (!detection.isWordPress) {
      return { isWordPress: false, skipped: 'Site does not appear to be running WordPress' };
    }

    // Extract initial data
    const versionInfo = extractVersion(html, response.headers);
    const themeName = extractTheme(html);

    // Run all security checks in parallel
    const [
      sensitiveFiles,
      xmlRpc,
      userEnumeration,
      directoryListing,
      restApi,
      plugins,
      theme,
    ] = await Promise.all([
      checkSensitiveFiles(baseUrl),
      checkXmlRpc(baseUrl),
      checkUserEnumeration(baseUrl),
      checkDirectoryListing(baseUrl),
      checkRestApi(baseUrl),
      checkPlugins(baseUrl, html),
      checkTheme(baseUrl, themeName),
    ]);

    // Check WordPress version vulnerabilities
    const wpVulns = checkVersionVulnerabilities('wordpress', null, versionInfo.version);

    const results = {
      isWordPress: true,
      detection,
      version: {
        detected: versionInfo.version,
        source: versionInfo.source,
        vulnerabilities: wpVulns,
      },
      theme,
      plugins,
      exposedFiles: sensitiveFiles,
      xmlRpc,
      userEnumeration,
      directoryListing,
      restApi,
    };

    // Calculate score and recommendations
    const { score, deductions } = calculateSecurityScore(results);
    results.securityScore = score;
    results.scoreDeductions = deductions;
    results.recommendations = generateRecommendations(results);

    return results;

  } catch (error) {
    throw new Error(`WordPress security scan failed: ${error.message}`);
  }
};

export const handler = middleware(wordpressSecurityHandler);
export default handler;
