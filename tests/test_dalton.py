
def test_dalton_about(client):
    response = client.get('/dalton/about')
    assert b'About Dalton' in response.data

