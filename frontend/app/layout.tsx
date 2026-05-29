export const metadata = {
  title: 'NeuroShield',
  description: 'Behavioral Transformer Ransomware Detection System',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body style={{ margin: 0, background: '#07080b' }}>{children}</body>
    </html>
  )
}
