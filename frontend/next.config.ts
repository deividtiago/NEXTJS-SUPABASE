import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  reactCompiler: true,
  redirects: async () =>{
    return [
    {
      source:"/logout",
      destination: "/auth/logout",
      permanent: true
    },
  ];
  }
};

export default nextConfig;
