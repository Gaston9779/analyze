export default ({ config }) => {
  const defaultApiBase = 'https://analysispdf-api.onrender.com';

  return {
    ...config,
    extra: {
      ...(config.extra || {}),
      apiBase: process.env.EXPO_PUBLIC_API_BASE || config.extra?.apiBase || defaultApiBase,
    },
  };
};
