.PHONY: install run test seed-reset

install:
	python -m pip install -r requirements.txt

run:
	streamlit run app4.py

test:
	python -m unittest discover -s tests -v

# Wipes local demo data and passwords; the app re-seeds on next start.
seed-reset:
	rm -rf auth.db employee_dbs initial_credentials.txt
