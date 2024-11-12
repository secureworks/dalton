import pytest
from app import create_app


@pytest.fixture(scope="class")
def client(request):
    the_app = create_app(
        {
            "TESTING": True,
        }
    )
    client = the_app.test_client()
    request.cls.client = client
