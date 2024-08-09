# Galapagos Frontend

This folder contains the Angular based frontend for Galapagos, which is automatically bundled into the application by
the `pom.xml` in the root directory.

This frontend is based on the great Angular / Bootstrap Template **SB Admin Angular**, see
[SB Admin Angular](https://startbootstrap.com/template/sb-admin-angular).

To start the Frontend during development, just run `npm run start` or `ng start` (if you have Angular CLI installed).
Afterwards, open http://localhost:4200 in your browser.

If you want to test the "production-like" behaviour of having the backend serving the frontend, run `mvn clean package` in
the root directory first, then run the GalapagosApplication (as described for the main application). Then, you can access
the frontend via http://localhost:8080/app/dashboard. But notice that this will not detect live-changes in the frontend code.
