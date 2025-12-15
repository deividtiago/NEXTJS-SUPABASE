import "./globals.css";
import { Header } from '../components/header';
import { Footer } from "../components/footer";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: 'Pagina do meu projeto',
  description: 'Descrição do projeto',
  openGraph: {
    title: 'Descrição completa do projeto aqui',
    description: 'projeto'
  },
  robots: {
    index: true,
    follow: true,
    nocache: true,
    googleBot:{
      index: true,
      follow: true,
    }
  }
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`antialiased`}
      >
        <Header />   
        {children}
        <Footer />
      </body>
    </html>
  );
}
