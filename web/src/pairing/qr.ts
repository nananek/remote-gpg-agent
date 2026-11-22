import qrcode from 'qrcode-generator';

/** QR の生成はクライアントで行う（秘密をサーバに渡さないため）。 */
export function renderQrSvg(text: string): string {
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  return qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
}
