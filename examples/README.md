# Examples

- `sample_zap_alerts.json` — example raw ZAP output, useful for testing the normalizer (R013/R014) without needing a live ZAP instance running.

For an end-to-end local test target, run [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) locally:

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

Then scan it: `riskrank scan http://localhost:3000`
