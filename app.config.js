export default ({ config }) => {
  return {
    ...config,
    extra: {
      ...(config.extra || {}),
      apiBase: process.env.EXPO_PUBLIC_API_BASE || config.extra?.apiBase || 'http://127.0.0.1:8787',
    },
  };
};
