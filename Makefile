SHELL := /bin/bash -euo pipefail
PROJECT := slack-thread-nuker

.DELETE_ON_ERROR:

.PHONY: test
test:
	python -m unittest discover . '*_test.py'

########################################
# AppEngine commands

.PHONY: serve
serve:
	dev_appserver.py --clear_datastore=1 .

.PHONY: deploy
deploy:
	gcloud app deploy --project=$(PROJECT) app.yaml

.PHONY: gc-no-traffic
gc-no-traffic:
	gcloud app versions delete --project=$(PROJECT) `gcloud app versions list --project=$(PROJECT) --format='csv[no-heading](VERSION.ID)' --filter='TRAFFIC_SPLIT=0 AND VERSION.ID!=dev'`

########################################
# Format and lint

.PHONY: fmt
fmt:
	@uvx --from scm-kit scm-format

.PHONY: lint
lint:
	@uvx --from scm-kit scm-lint

.PHONY: lint-all
lint-all:
	@uvx --from scm-kit scm-lint -a
