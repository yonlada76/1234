// public/js/scan-capacitor.js
import { BarcodeScanner } from '@capacitor-community/barcode-scanner';

export async function startScanCapacitor(targetNext) {
  try {
    await BarcodeScanner.checkPermission({ force: true });
    await BarcodeScanner.hideBackground();
    const result = await BarcodeScanner.startScan();
    await BarcodeScanner.showBackground();
    await BarcodeScanner.stopScan();

    if (result?.hasContent) {
      const code = result.content.trim();
      window.location.replace(`${targetNext}?member=${encodeURIComponent(code)}`);
    }
  } catch (e) {
    console.error(e);
    await BarcodeScanner.showBackground();
    await BarcodeScanner.stopScan();
    alert('สแกนไม่สำเร็จ: ' + (e.message || e));
  }
}
