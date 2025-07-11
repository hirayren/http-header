import requests

required_headers = {
    "Content-Security-Policy": "XSS'e karşı koruma",
    "Strict-Transport-Security": "HTTPS zorlaması (HSTS)",
    "X-Frame-Options": "Clickjacking'e karşı koruma",
    "X-Content-Type-Options": "MIME sniffing'e karşı koruma",
    "Referrer-Policy": "Yönlendirme bilgilerini sınırlar",
    "Permissions-Policy": "Tarayıcı API erişimlerini sınırlar"
}

risk_info = {
    "Content-Security-Policy": "❗ XSS saldırılarına açık olabilir.",
    "Strict-Transport-Security": "❗ Downgrade / MITM saldırılarına açık olabilir.",
    "X-Frame-Options": "❗ Clickjacking saldırılarına açık olabilir.",
    "X-Content-Type-Options": "❗ MIME sniffing ile zararlı içerik çalıştırılabilir.",
    "Referrer-Policy": "❗ URL bilgileri sızabilir.",
    "Permissions-Policy": "❗ Kamera, mikrofon gibi API’lara izinsiz erişim olabilir."
}

advanced_headers = {
    "Expect-CT": "Sertifika şeffaflığı için",
    "Cross-Origin-Resource-Policy": "Kaynak paylaşımı kontrolü",
    "Cross-Origin-Embedder-Policy": "Modern API koruması",
    "Cross-Origin-Opener-Policy": "Sekme izolasyonu",
    "Cache-Control": "Önbellek sınırlandırması",
    "Access-Control-Allow-Origin": "CORS kontrolü"
}

def analyze_security_headers(url, include_advanced=False):
    try:
        response = requests.get(url)
        headers = response.headers

        print("\nTemel Güvenlik Başlıkları Analizi:\n")
        for header, explanation in required_headers.items():
            if header in headers:
                print(f"[+] {header} bulundu → {explanation}")
            else:
                print(f"[-] {header} EKSİK → {explanation}")
                print(f"    {risk_info[header]}\n")

        if include_advanced:
            print("\nGelişmiş Güvenlik Başlıkları:\n")
            for header, explanation in advanced_headers.items():
                if header in headers:
                    print(f"[+] {header} bulundu → {explanation}")
                else:
                    print(f"[-] {header} eksik (opsiyonel)")

    except requests.exceptions.RequestException as e:
        print("[-] HTTP isteği başarısız:", e)

def search_cve_by_keyword(keyword):
    print("\nCVE Araması (Vendor: {})".format(keyword.capitalize()))
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{keyword}")
        data = response.json()
        results = data.get("data", [])[:5]

        if results:
            for i, cve in enumerate(results, 1):
                print(f"[{i}] {cve['id']}: {cve.get('summary', 'Açıklama bulunamadı')}")
        else:
            print("Bu anahtar kelimeyle eşleşen CVE bulunamadı.")

    except Exception as e:
        print("[-] CVE verileri alınamadı:", e)


if __name__ == "__main__":
    while True:
        url = input("\nLütfen bir URL girin (örn: https://example.com): ").strip()

        gelişmiş = input("Gelişmiş başlıkları da kontrol et: (e/h): ").strip().lower()
        include_advanced = gelişmiş == "e"

        analyze_security_headers(url, include_advanced)

        try:
            domain = url.split("//")[-1].split("/")[0]
            vendor_keyword = domain.split(".")[-2]
            search_cve_by_keyword(vendor_keyword)
        except Exception as e:
            print("[-] Vendor adı alınamadı:", e)

        cont = input("\n↪Yeni bir URL denemek ister misiniz? (e/h): ").strip().lower()
        if cont != 'e':
            print("Programdan çıkış yaptınız.")
            break