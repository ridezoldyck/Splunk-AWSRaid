# Laporan Investigasi Insiden — AWSRaid

## Ringkasan Eksekutif

Pencarian menggunakan Splunk terhadap dataset AWS CloudTrail dari CTF AWSRaid mengidentifikasi aktivitas autentikasi yang mencurigakan pada akun `helpdesk.luke`, pengambilan objek dari Amazon S3, peristiwa `PutBucketPublicAccessBlock` pada bucket `backup-and-restore98825501`, serta pembuatan akun IAM baru bernama `marketing.mark` yang kemudian ditambahkan ke grup `Admins`.

Rangkaian aktivitas tersebut mengindikasikan kemungkinan kompromi akun, akses terhadap objek penyimpanan cloud, perubahan konfigurasi keamanan, dan peningkatan hak akses. Seluruh temuan perlu dievaluasi berdasarkan bukti log yang tersedia.

## Temuan Investigasi

1. **Akun yang diduga dikompromikan:** `helpdesk.luke` diidentifikasi sebagai akun yang mencurigakan dalam skenario CTF.
2. **Akses objek S3 pertama yang ditampilkan:** Peristiwa `GetObject` pertama pada hasil pencarian yang diperiksa tercatat pada `2023-11-02 09:55:53`.
3. **Pengambilan file DWG:** File `Product2_CAD_Designs.dwg` diambil dari bucket `product-designs-repository31183937`.
4. **Perubahan konfigurasi keamanan S3:** Peristiwa `PutBucketPublicAccessBlock` tercatat pada bucket `backup-and-restore98825501`.
5. **Pembuatan akun dan perubahan hak akses IAM:** Akun `marketing.mark` dibuat dan kemudian ditambahkan ke grup `Admins`.

## Penilaian Insiden

Kombinasi aktivitas autentikasi yang mencurigakan, pengambilan objek S3, perubahan konfigurasi bucket, dan penambahan akun ke grup administratif memerlukan investigasi lebih lanjut dengan prioritas tinggi.

Namun, tangkapan layar yang tersedia hanya memperlihatkan sebagian informasi dari hasil pencarian Splunk. Peristiwa `PutBucketPublicAccessBlock` saja tidak membuktikan bahwa bucket menjadi dapat diakses publik. Untuk memastikan dampaknya, diperlukan pemeriksaan terhadap detail peristiwa CloudTrail, parameter konfigurasi yang diubah, kebijakan bucket, ACL, dan pengaturan akses publik pada tingkat akun.

Demikian pula, penambahan pengguna ke grup `Admins` menunjukkan perubahan keanggotaan grup, tetapi tingkat hak akses sebenarnya bergantung pada kebijakan IAM yang diterapkan.

## Rekomendasi Tindakan

1. **Amankan bukti:** Simpan log CloudTrail dan log pendukung yang relevan untuk menjaga kelengkapan bukti investigasi.
2. **Verifikasi aktivitas login:** Periksa alamat IP sumber, status MFA, user agent, waktu kejadian, dan konteks sesi untuk menentukan apakah login dilakukan secara sah.
3. **Lakukan penanganan akun yang terkompromikan:** Jika kompromi terkonfirmasi, amankan kredensial, cabut sesi aktif jika diperlukan, dan tinjau seluruh aktivitas akun tersebut.
4. **Audit akun IAM baru:** Periksa akun `marketing.mark`, access key, kebijakan IAM, serta keanggotaan grupnya. Hapus akses yang tidak sah setelah diverifikasi.
5. **Periksa konfigurasi keamanan S3:** Tinjau konfigurasi pemblokiran akses publik, kebijakan bucket, ACL, dan log akses untuk memastikan apakah terjadi paparan data.
6. **Evaluasi objek yang diakses:** Identifikasi sensitivitas file yang diambil dan cari indikasi pengambilan data tanpa izin atau eksfiltrasi data.
7. **Dokumentasikan penanganan:** Catat temuan, tindakan mitigasi, hasil pemulihan, dan rekomendasi pencegahan untuk mengurangi risiko insiden serupa.

## Keterbatasan Investigasi

- Timestamp disalin dari tangkapan layar Splunk. Zona waktu belum diverifikasi secara independen.
- Tangkapan layar hanya menampilkan sebagian bidang dari peristiwa yang diperiksa.
- Dataset mentah AWS CloudTrail dan ekspor log asli tidak disertakan dalam repository ini.
- Status akses publik bucket belum dapat dipastikan hanya berdasarkan peristiwa perubahan konfigurasi.
- Kesimpulan mengenai kompromi akun dan dampak aktivitas perlu dikonfirmasi melalui pemeriksaan log lengkap serta konteks tambahan.

## Kesimpulan

Investigasi AWSRaid menunjukkan beberapa indikator aktivitas mencurigakan, termasuk autentikasi yang perlu diperiksa, pengambilan objek S3, perubahan konfigurasi keamanan bucket, serta pembuatan akun IAM baru yang ditambahkan ke grup administratif.

Latihan ini memberikan pengalaman praktis dalam menggunakan Splunk untuk menganalisis log AWS CloudTrail, menyusun linimasa aktivitas, mengidentifikasi perubahan hak akses, dan merumuskan rekomendasi respons insiden.

**Disclaimer:** Laporan ini dibuat sebagai dokumentasi pembelajaran menggunakan dataset CTF yang sengaja disiapkan untuk latihan. Temuan di dalamnya bukan bukti aktivitas pada akun AWS nyata.
