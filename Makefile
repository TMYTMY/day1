.PHONY: run test seed

run:
	python -m streamlit run app.py

test:
	python -m pip install -q -r requirements-dev.txt
	python -m pytest

seed:
	python -m src.db.seed
