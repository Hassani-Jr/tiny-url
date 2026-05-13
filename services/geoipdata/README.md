# GeoIP data

`GeoLite2-Country.mmdb` is embedded at build time and used by the redirect
handler to enrich each click event with a country code (ISO 3166-1
alpha-2, e.g. `US`, `DE`, `JP`).

## Placeholder

The committed `.mmdb` is a **zero-byte placeholder**. With this file in
place, the binary builds and runs but `GeoIP.Country(ip)` returns `""` —
country enrichment is a no-op. The rest of the click analytics pipeline
(counts, referers, devices) is unaffected.

## Production builds

Before building a release binary, replace the placeholder with the
genuine GeoLite2-Country database from MaxMind:

1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. Generate a license key under **Account → Manage License Keys**
3. Download the latest country DB:

   ```
   curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz" \
     | tar -xz --strip-components=1 -C services/geoipdata GeoLite2-Country_*/GeoLite2-Country.mmdb
   ```

4. Rebuild the binary. Country enrichment turns on automatically.

The file should be ~6 MB. The build embeds it into the binary; no
runtime file dependency.

## License

GeoLite2 is © MaxMind, distributed under their End User License Agreement.
You must accept the EULA before redistributing binaries built with the
real database. See https://www.maxmind.com/en/geolite2/eula.
