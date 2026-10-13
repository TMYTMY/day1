.PHONY: run test seed

run:
	python -m streamlit run app.py

test:
	pytest

seed:
	python -m src.db.seed
