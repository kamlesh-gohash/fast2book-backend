## Fast2book Frontend

Version 0.0.1

1. To install dependencies

```
poetry install
```

2. To run project

```
poetry run uvicorn app.main:app --port 8000 --reload
```

3. To check formatting 

```
poetry run black --check .
```

4. To format code 

```
poetry run black .
```

5. To run test

```
poetry run pytest
```