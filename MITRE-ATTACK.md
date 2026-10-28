# Pemetaan Potensial MITRE ATT&CK

Pemetaan berikut merupakan analisis awal untuk keperluan portofolio. Pemetaan ini bukan bukti pasti mengenai niat atau tindakan penyerang.

| Perilaku yang Diamati | Teknik Potensial | Alasan |
|---|---|---|
| Kegagalan autentikasi berulang | **T1110 — Brute Force** (Serangan Brute Force) | Perlu memvalidasi urutan percobaan login dan konteks alamat IP sumber untuk menentukan apakah terdapat indikasi serangan brute force. |
| Pembuatan akun IAM baru | **T1136.003 — Create Account: Cloud Account** (Membuat Akun: Akun Cloud) | Pembuatan akun cloud yang tidak sah dapat digunakan untuk mempertahankan akses ke lingkungan yang telah dikompromikan (*persistence*). |
| Pengguna ditambahkan ke grup `Admins` | **T1098 — Account Manipulation** (Manipulasi Akun) | Perubahan keanggotaan grup dapat meningkatkan hak akses pengguna, bergantung pada kebijakan dan izin yang diberikan kepada grup tersebut. |
| Pengambilan objek dari Amazon S3 | **T1530 — Data from Cloud Storage** (Pengambilan Data dari Penyimpanan Cloud) | Teknik ini relevan apabila penyerang mengakses data yang tersimpan di layanan penyimpanan cloud tanpa otorisasi. |
| Perubahan konfigurasi pemblokiran akses publik S3 | **Memerlukan validasi lebih lanjut** | Periksa parameter konfigurasi sebelum menentukan teknik yang sesuai. Perubahan pengaturan saja belum membuktikan bahwa bucket menjadi dapat diakses publik. |

## Catatan Analisis

Pemetaan MITRE ATT&CK harus didasarkan pada bukti yang tersedia dan konteks aktivitas. Nama peristiwa CloudTrail saja tidak selalu cukup untuk memastikan teknik yang digunakan.

Sebelum menggunakan pemetaan ini dalam laporan investigasi formal, periksa kembali dokumentasi MITRE ATT&CK terbaru dan pastikan setiap teknik didukung oleh bukti yang relevan.
