# AWSRaid — Investigasi AWS CloudTrail

**Portofolio:** Junior SOC Analyst / Blue Team  
**Tools:** Splunk, AWS CloudTrail, SPL (Search Processing Language)  
**Lab:** CyberDefenders AWSRaid CTF

## Ringkasan

Proyek ini mendokumentasikan investigasi aktivitas mencurigakan pada lingkungan AWS menggunakan log AWS CloudTrail yang dianalisis melalui Splunk. Investigasi berfokus pada aktivitas autentikasi yang mencurigakan, pengambilan objek dari Amazon S3, perubahan konfigurasi keamanan bucket, serta pembuatan akun IAM baru yang ditambahkan ke grup administratif.

Proyek ini bertujuan untuk melatih kemampuan analisis log, identifikasi indikasi kompromi akun, penelusuran aktivitas penyerang, dan penyusunan laporan insiden keamanan.

## Temuan Utama

| Temuan | Hasil |
|---|---|
| Akun yang diduga telah dikompromikan | `helpdesk.luke` |
| Akses S3 `GetObject` pertama pada hasil yang diperiksa | `2023-11-02 09:55:53` |
| Bucket yang berisi file DWG | `product-designs-repository31183937` |
| Bucket dengan peristiwa `PutBucketPublicAccessBlock` | `backup-and-restore98825501` |
| Akun IAM baru yang dibuat | `marketing.mark` |
| Perubahan keanggotaan grup | `marketing.mark` ditambahkan ke grup `Admins` |

**Catatan penting:** Peristiwa `PutBucketPublicAccessBlock` menunjukkan adanya perubahan konfigurasi pemblokiran akses publik. Peristiwa ini saja belum membuktikan bahwa bucket benar-benar menjadi publik. Untuk memastikannya, perlu diperiksa parameter permintaan, kebijakan bucket, ACL, dan konfigurasi tingkat akun. Timestamp di atas disalin dari tangkapan layar Splunk; zona waktu perlu diverifikasi sebelum digunakan untuk korelasi dengan sumber lain.

## Proses Investigasi

### 1. Mengidentifikasi kegagalan autentikasi

Kueri berikut digunakan untuk menghitung jumlah kegagalan autentikasi berdasarkan nama pengguna.

```spl
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication"
| stats count by userIdentity.userName
| sort -count
```

**Tujuan:** Mengidentifikasi akun dengan jumlah kegagalan autentikasi tertinggi untuk menentukan akun yang perlu diperiksa lebih lanjut.

### 2. Memeriksa riwayat login akun

```spl
index="aws_cloudtrail" eventSource="signin.amazonaws.com" "userIdentity.userName"="helpdesk.luke"
| table _time userIdentity.userName errorMessage responseElements.ConsoleLogin sourceIPAddress
| sort _time
```

**Tujuan:** Menelusuri urutan percobaan login, status autentikasi, waktu kejadian, dan alamat IP sumber.

### 3. Menelusuri akses objek S3

```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject"
| table _time eventName requestParameters.bucketName requestParameters.key
| sort _time
```

**Tujuan:** Mengidentifikasi objek yang diakses, bucket terkait, dan waktu pengambilan objek.

### 4. Mengidentifikasi bucket yang berisi file DWG

```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" "*.dwg"
| table _time requestParameters.bucketName requestParameters.key
```

**Hasil:** File `Product2_CAD_Designs.dwg` ditemukan pada bucket `product-designs-repository31183937`.

**Tujuan:** Menelusuri akses terhadap file tertentu yang berpotensi memiliki nilai penting bagi organisasi.

### 5. Memeriksa perubahan konfigurasi akses publik S3

```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName="PutBucketPublicAccessBlock"
| table _time requestParameters.bucketName userIdentity.arn
```

**Hasil:** Ditemukan peristiwa perubahan konfigurasi pada bucket `backup-and-restore98825501`.

**Tujuan:** Mengidentifikasi perubahan konfigurasi keamanan yang perlu ditinjau untuk menentukan apakah perubahan tersebut meningkatkan risiko paparan data.

### 6. Mengidentifikasi pembuatan akun IAM baru

```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management"
| search eventName="CreateUser" OR eventName="CreateLoginProfile"
| table _time eventName requestParameters.userName
| sort _time
```

**Hasil:** Akun IAM baru yang teridentifikasi adalah `marketing.mark`.

**Tujuan:** Menemukan kemungkinan upaya mempertahankan akses melalui pembuatan identitas baru.

### 7. Memeriksa penambahan pengguna ke grup

```spl
index="aws_cloudtrail" eventName="AddUserToGroup"
| table _time requestParameters.groupName requestParameters.userName
```

**Hasil:** Akun `marketing.mark` ditambahkan ke grup `Admins`.

**Tujuan:** Mengidentifikasi perubahan keanggotaan grup yang dapat meningkatkan hak akses pengguna. Dampak sebenarnya bergantung pada kebijakan IAM yang melekat pada grup tersebut.

## Linimasa Investigasi

Linimasa berikut disusun berdasarkan hasil pencarian yang terlihat pada tangkapan layar Splunk.

| Timestamp yang ditampilkan | Aktivitas |
|---|---|
| `2023-11-02 09:55:53` | Akses `GetObject` pertama pada hasil yang diperiksa |
| `2023-11-02 09:56:07` | File `Product2_CAD_Designs.dwg` diambil dari bucket `product-designs-repository31183937` |
| `2023-11-02 09:58:01` | Perubahan konfigurasi `PutBucketPublicAccessBlock` pada bucket `backup-and-restore98825501` |
| `2023-11-02 09:59:38` | Akun `marketing.mark` ditambahkan ke grup `Admins` |

**Catatan:** Linimasa ini mencerminkan hasil yang diperiksa, bukan keseluruhan aktivitas dalam lingkungan AWS. Zona waktu dan urutan lengkap peristiwa perlu diverifikasi melalui log asli.

## Analisis dan Rekomendasi Respons

Berdasarkan temuan dalam simulasi ini, beberapa tindakan yang dapat dilakukan oleh tim SOC adalah:

- Memverifikasi apakah aktivitas login berasal dari pengguna yang sah dengan memeriksa alamat IP sumber, status MFA, user agent, dan konteks sesi.
- Mengamankan serta mempertahankan log CloudTrail dan bukti pendukung untuk kebutuhan investigasi.
- Menonaktifkan atau merotasi kredensial identitas yang terbukti dikompromikan serta mencabut sesi aktif jika diperlukan.
- Memeriksa akun `marketing.mark`, termasuk access key, kebijakan IAM, dan keanggotaan grupnya.
- Meninjau perubahan konfigurasi S3, kebijakan bucket, ACL, serta pengaturan akses publik untuk memastikan dampak perubahan.
- Memeriksa sensitivitas objek yang diakses dan mencari bukti kemungkinan pengambilan atau eksfiltrasi data.
- Mendokumentasikan proses penanganan, pemulihan, dan rekomendasi pencegahan agar insiden serupa dapat dideteksi lebih awal.

## Keterampilan yang Dipraktikkan

- Analisis log menggunakan Splunk SPL.
- Investigasi AWS CloudTrail.
- Analisis anomali autentikasi.
- Penelusuran akses objek Amazon S3.
- Investigasi perubahan konfigurasi keamanan cloud.
- Analisis pembuatan akun IAM dan perubahan hak akses.
- Penyusunan linimasa insiden.
- Dokumentasi temuan dan rekomendasi respons insiden.

## Bukti Investigasi

Tangkapan layar hasil pencarian Splunk disimpan di folder [`evidence/`](evidence/). Bukti tersebut mencakup:

- Riwayat autentikasi akun yang diperiksa.
- Aktivitas pengambilan objek S3.
- File DWG beserta bucket terkait.
- Perubahan konfigurasi pemblokiran akses publik S3.
- Penambahan akun baru ke grup `Admins`.

## Disclaimer

Proyek ini merupakan latihan analisis keamanan berbasis dataset CTF yang sengaja dibuat untuk pembelajaran. Temuan di dalamnya bukan bukti aktivitas pada akun AWS nyata. Jangan mengunggah dataset mentah, kredensial, token sesi, atau informasi sensitif ke repository publik.
