# PoisonXSS

![PoisonXSS Banner](https://github.com/mkhairin/poisonxss/blob/main/img/banner.png)

PoisonXSS adalah tool scanner kerentanan Cross-Site Scripting (XSS) dan HTML Injection yang cepat, fleksibel, dan cerdas. Dibangun dengan Python dan `asyncio`, PoisonXSS mampu melakukan pemindaian secara konkuren untuk efisiensi maksimal.

Dengan fitur-fitur seperti web crawler otomatis, identifikasi teknologi, dan berbagai mode pengujian, PoisonXSS dirancang untuk para profesional keamanan, bug hunter, dan pengembang web untuk menguji keamanan aplikasi web secara mendalam.

## ✨ Fitur Unggulan

- **Pemindaian Asinkron:** Sangat cepat berkat `asyncio` dan `aiohttp`, mampu menangani banyak request secara bersamaan.
- **Dua Mode Pengujian:** Mendukung pengujian untuk **XSS** dan **HTML Injection** secara spesifik.
- **Web Crawler (Spider):** Mampu menjelajahi situs target secara otomatis untuk menemukan dan menguji halaman-halaman baru.
- **Intelijen & Fingerprinting:** Dapat mengidentifikasi teknologi yang digunakan oleh server (misalnya, Apache, Nginx, WordPress) untuk memberikan konteks pada temuan.
- **Dua Mode Target:** Mendukung pengujian pada satu URL sebagai titik awal (`-u`) atau pada daftar URL yang telah ditentukan (`-l`).
- **Kontrol Profesional:** Dukungan penuh untuk proxy, kustomisasi header, pengaturan delay antar request, verbose mode, dan jumlah worker.
- **Payload Kustom:** Gunakan daftar payload Anda sendiri dari sebuah file untuk pengujian yang fleksibel.
- **Laporan:** Menyimpan hasil pemindaian ke dalam file `.txt` untuk dokumentasi dan analisis lebih lanjut.

## ⚙️ Instalasi

Proses instalasi sangat mudah dan cepat.

1.  **Clone Repositori:**
    ```bash
    git clone [https://github.com/mkhairin/poisonxss](https://github.com/mkhairin/poisonxss)
    cd poisonxss
    ```

2.  **Instal Dependensi:**
    Jalankan perintah berikut di terminal Anda. Ini akan secara otomatis menginstal semua library yang dibutuhkan dari file `requirements.txt` yang sudah ada.
    ```bash
    pip install -r requirements.txt
    ```
    Sekarang Anda siap untuk menjalankan PoisonXSS.

## 🚀 Cara Menjalankan

Gunakan sintaks dasar berikut untuk menjalankan pemindaian:
```bash
python poisonxss.py [TARGET] [PAYLOADS] [OPTIONS]
```

### Opsi Perintah

| Flag(s)                         | Deskripsi                                                        |
| ------------------------------- | ---------------------------------------------------------------- |
| **Target (Pilih salah satu)** |                                                                  |
| `-u URL`, `--url=URL`           | URL awal tunggal untuk pemindaian atau *crawling*.               |
| `-l FILE`, `--list=FILE`        | File berisi daftar URL untuk diuji.                              |
| **Payloads** |                                                                  |
| `-p FILE`, `--payloads=FILE`    | File berisi *payload* XSS (mode default).                        |
| `--payloads-htmli=FILE`         | File berisi *payload* HTML Injection (untuk mode `--htmli`).     |
| **Mode Pengujian** |                                                                  |
| `--htmli`                       | Mengganti mode pengujian ke HTML Injection.                      |
| **Crawler (Hanya dengan `-u`)** |                                                                  |
| `--crawl`                       | Mengaktifkan *web crawler* dari URL awal.                        |
| `--depth=DEPTH`                 | Kedalaman *crawl* maksimum (default: 2).                         |
| **Intelijen** |                                                                  |
| `--fingerprint`                 | Mengaktifkan identifikasi teknologi (*fingerprinting*).          |
| **Request & Kontrol** |                                                                  |
| `-H HEADERS`, `--headers=HEADERS` | *Header* kustom, pisahkan dengan koma (cth: `"Cookie:id=123"`).  |
| `--proxy=PROXY`                 | Menggunakan *proxy* (cth: `http://127.0.0.1:8080`).               |
| `-v`, `--verbose`               | Menampilkan output detail, termasuk *request* yang aman.         |
| `--delay=DELAY`                 | Jeda dalam detik di antara setiap *request*.                     |
| `-w NUM`, `--workers=NUM`       | Jumlah *worker* konkuren (default: 50).                          |
| `-o FILE`, `--output=FILE`      | Menyimpan laporan pemindaian ke sebuah file.                     |
| **Lainnya** |                                                                  |
| `--help-syntax`                 | Menampilkan panduan bantuan ini.                                 |
| `--version`                     | Menampilkan nomor versi program.                                 |

### Contoh Penggunaan

**1. Pemindaian XSS Dasar pada Satu URL**
```bash
python poisonxss.py -u "[http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1)" -p payloads.txt
```

**2. Pemindaian pada Daftar URL dari File**
```bash
python poisonxss.py -l urls.txt -p payloads.txt -v
```

**3. Menjalankan Crawler dengan Kedalaman 3**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) -p payloads.txt --crawl --depth 3
```

**4. Pemindaian HTML Injection Menggunakan Payload Bawaan**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) --htmli
```

**5. Pemindaian Lanjutan: Crawler + Fingerprinting + Verbose + Proxy**
```bash
python poisonxss.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) -p payloads.txt --crawl --fingerprint -v --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080)
```

## ⚠️ Catatan

- **Izin:** Gunakan *tool* ini hanya untuk tujuan yang sah, seperti menguji keamanan aplikasi web Anda sendiri atau dengan izin eksplisit dari pemilik aplikasi.
- **Tanggung Jawab:** Anda bertanggung jawab penuh atas penggunaan *tool* ini.

## Lizensi

Proyek ini dilisensikan di bawah Lisensi MIT.

## Kontribusi

Kontribusi selalu diterima! Lakukan *fork* pada repositori ini, buat perubahan Anda, dan kirimkan *pull request*.
