# CleanRoute - TODO

## Phase 2 (Backend) — Images + Address support
- [x] Update `server.js` to add `multer` multipart middleware.
- [x] Update `routes/litter.js` POST `/report` to accept multer upload (attached in server.js).
- [x] Update `controllers/litterController.js`:
  - [x] Change required fields from `latitude/longitude` to `address`.
  - [x] Accept optional uploaded `images`.
  - [x] Store `address` (and images metadata) in report object.
- [x] Update validation error messages accordingly.
- [x] Smoke test:
  - [x] Submit report with address via curl.
  - [x] Confirm API returns 201 and report saved in-memory.
  - [x] Confirm `/api/litter/stats` works.



