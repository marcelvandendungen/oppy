from oppy.app import app

import pytest

@pytest.fixture(scope='module')
def test_client(): 
    testing_client = app.test_client()
 
    ctx = app.app_context()
    ctx.push()
 
    yield testing_client
 
    ctx.pop()
