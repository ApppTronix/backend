
import pymongo
client = pymongo.MongoClient()

client.copyDatabase('mydatabase', 'nitkdb')

assert set(client['mydatabase'].collection_names()) == set(client['nitkdb'].collection_names())

for collection in client['mydatabase'].collection_names():
    assert client['mydatabase'][collection].count() == client['nitkdb'][collection].count()

#client.drop_database('mydatabase')