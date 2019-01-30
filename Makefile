KUBECTL = kubectl
STEP = step

TARGET = target
TRUST_DOMAIN ?= example.com

CA_CRT = $(TARGET)/$(TRUST_DOMAIN)/ca.crt
CA_KEY = $(TARGET)/$(TRUST_DOMAIN)/ca.key

SIGNING_CRT = $(TARGET)/$(TRUST_DOMAIN)/signing.crt
SIGNING_KEY = $(TARGET)/$(TRUST_DOMAIN)/signing.key
SIGNING_YML = $(TARGET)/$(TRUST_DOMAIN)/l5d-id-signing-key.yml
TRUST_YML = $(TARGET)/$(TRUST_DOMAIN)/l5d-id-trust.yml
K8S_YML = $(TARGET)/$(TRUST_DOMAIN)/k8s.yml

.PHONY: $(TRUST_DOMAIN)
$(TRUST_DOMAIN): $(TARGET)/$(TRUST_DOMAIN)

$(TARGET)/$(TRUST_DOMAIN): $(SIGNING_YML)

.PHONY: clean
clean: clean-ca
	rm -rf $(TARGET)

.PHONY: clean-ca
clean-ca:
	rm -rf $(TARGET)/$(TRUST_DOMAIN)

.PHONY: ca
ca: $(CA_CRT) $(CA_KEY) $(TRUST_YML)
	step certificate inspect $(CA_CRT)

$(CA_CRT) $(CA_KEY):
	mkdir -p $(TARGET)/$(TRUST_DOMAIN)
	$(STEP) certificate create --profile root-ca $(TRUST_DOMAIN) $(CA_CRT) $(CA_KEY)

.PHONY: clean-signing
clean-signing-key:
	rm -rf $(SIGNING_CRT) $(SIGNING_KEY) $(SIGNING_YML)

.PHONY: signing
signing-key: ca $(SIGNING_CRT) $(SIGNING_KEY) $(SIGNING_YML)
	step certificate inspect $(SIGNING_CRT)

$(SIGNING_CRT) $(SIGNING_KEY): $(CA_CRT)
	$(STEP) certificate create --profile intermediate-ca \
		--insecure --no-password \
		--ca-key $(CA_KEY) --ca $(CA_CRT) \
		$(TRUST_DOMAIN) $(SIGNING_CRT) $(SIGNING_KEY)

$(SIGNING_YML): $(SIGNING_CRT) $(SIGNING_KEY)
	sh mksecret.sh $(SIGNING_KEY) $(SIGNING_CRT) >$(SIGNING_YML)

$(TRUST_YML): $(CA_CRT)
	sh mktrust.sh $(CA_CRT) >$(TRUST_YML)

$(K8S_YML): k8s.yml $(TRUST_YML) $(SIGNING_YML)
	cat k8s.yml $(TRUST_YML) $(SIGNING_YML) >$(K8S_YML)

.PHONY: k8s
k8s: $(K8S_YML)

.PHONY: vendor
vendor:
	dep ensure

docker: vendor
	docker build -t olix0r/l5d-id:latest .

