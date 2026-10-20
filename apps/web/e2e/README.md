# Browser workflows

From `apps/web`, using Node 20 or 22:

```sh
npm ci
npm run test:e2e
```

`test:e2e` first runs `playwright install chromium` (`pretest:e2e`), which
fetches the Chromium build this Playwright version pins on the first run and is a
no-op after that. It is deliberately not a `postinstall`: the production web
image runs `npm ci` too, and must not download a browser.

Playwright builds a separate `.next-e2e` output and starts the production UI on
`127.0.0.1:3107`. An occupied port fails rather than reusing another application.
All API responses are intercepted at `http://api.test`; other external requests
are blocked and fail the test. No scan is sent to a live target. Tests cover the
wizard, credential submission, all run flags, fresh authorization on panel open,
progress polling, cancellation, API-error recovery and a JSON report download.
These are UI workflow tests with a mocked server; backend contracts and worker
execution are tested separately. No retries hide failures. Failure traces are
saved in `test-results` and uploaded by CI.

Do not change the API URL to point these tests at a deployed scanner. Add new
response fixtures and explicit route handlers when a workflow gains an API call.
