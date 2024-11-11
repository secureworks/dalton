
def test_flowsynth_about(client):
    response = client.get('/flowsynth/about')
    assert b'About Flowsynth' in response.data

def test_flowsynth_compile(client):
    response = client.get('/flowsynth/compile')
    assert b'Compile' in response.data

def test_flowsynth_build(client):
    response = client.get('/flowsynth/')
    assert b'Build Packet Capture' in response.data
