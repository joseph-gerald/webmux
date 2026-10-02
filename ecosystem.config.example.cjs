module.exports = {
  apps: [{
    name: 'webmux',
    script: './server.js',
    cwd: __dirname,
    exec_mode: 'fork',
    instances: 1,
    watch: false,
    env: {
      PORT: process.env.PORT || '7070',
      WEBMUX_HOST: process.env.WEBMUX_HOST || '127.0.0.1',
      WEBMUX_PUBLIC_URL: process.env.WEBMUX_PUBLIC_URL || 'http://localhost:7070',
      // Set WEBMUX_TRUST_PROXY=loopback for a reverse proxy on this machine.
      // Secrets, local paths and external provider configuration belong in env.
    },
  }],
};
