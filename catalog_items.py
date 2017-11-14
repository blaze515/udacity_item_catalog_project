from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, CatalogItem, Category

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Literate John",
             email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543'
                     '/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Book category
category1 = Category(user_id=User1.id, name="Books")

session.add(category1)
session.commit()

book1 = CatalogItem(user_id=User1.id,
                    name="One Hundred Years of Solitude",
                    description='One Hundred Years of Solitude is a landmark '
                                '1967 novel by Colombian author Gabriel '
                                'Garcia Marquez.',
                    category=category1)

session.add(book1)
session.commit()

book2 = CatalogItem(user_id=User1.id,
                    name="Atonement",
                    description='Atonement is a 2001 British metafiction '
                                'novel written by Ian McEwan concerning the '
                                'understanding of and responding to the need '
                                'for personal atonement.',
                    category=category1)

session.add(book2)
session.commit()

book3 = CatalogItem(user_id=User1.id,
                    name="The Road",
                    description='The Road is a 2006 novel by American writer '
                                'Cormac McCarthy. It is a post-apocalyptic '
                                'tale of a journey of a father and his young '
                                'son over a period of several months',
                    category=category1)

session.add(book3)
session.commit()

book4 = CatalogItem(user_id=User1.id,
                    name="The Brief Wondrous Life of Oscar Wao",
                    description='The Brief Wondrous Life of Oscar Wao is a '
                                'novel written by Dominican American author '
                                'Junot Diaz.',
                    category=category1)

session.add(book4)
session.commit()

book4 = CatalogItem(user_id=User1.id,
                    name="The Great Gatsby",
                    description='The Great Gatsby is a 1925 novel written by '
                                'American author F. Scott Fitzgerald that '
                                'follows a cast of characters living in the '
                                'fictional town of West Egg on prosperous '
                                'Long Island in the summer of 1922.',
                    category=category1)

session.add(book4)
session.commit()

book4 = CatalogItem(user_id=User1.id,
                    name='The Aeneid',
                    description='The Aeneid is a Latin epic poem, written by '
                                'Virgil between 29 and 19 BC, that tells the '
                                'legendary story of Aeneas, a Trojan who '
                                'traveled to Italy, where he became the '
                                'ancestor of the Romans.',
                    category=category1)

session.add(book4)
session.commit()

book4 = CatalogItem(user_id=User1.id,
                    name="The Joy Luck Club",
                    description='The Joy Luck Club is a 1989 novel written '
                                'by Amy Tan. It focuses on four Chinese '
                                'American immigrant families in San '
                                'Francisco who start a club known as The Joy '
                                'Luck Club, playing the Chinese game of '
                                'mahjong for money while feasting on various '
                                'foods.',
                    category=category1)

session.add(book4)
session.commit()

# Shoe category
category2 = Category(user_id=User1.id, name="Shoes")

session.add(category2)
session.commit()

shoe1 = CatalogItem(user_id=User1.id,
                    name="Nike Air VaporMax Flyknit",
                    description='Men\'s Running Shoe',
                    category=category2)

session.add(shoe1)
session.commit()

shoe2 = CatalogItem(user_id=User1.id,
                    name="Aldo Umelilian",
                    description='Men\'s Oxford Shoe',
                    category=category2)

session.add(shoe2)
session.commit()

shoe3 = CatalogItem(user_id=User1.id,
                    name="Aldo Masen",
                    description='Women\'s Boot',
                    category=category2)

session.add(shoe3)
session.commit()

shoe4 = CatalogItem(user_id=User1.id,
                    name="Nike Air Jordan 12 Retro",
                    description='Men\'s Shoe',
                    category=category2)

session.add(shoe4)
session.commit()

# Music category
category3 = Category(user_id=User1.id, name="Music")

session.add(category3)
session.commit()

music1 = CatalogItem(user_id=User1.id,
                     name="Paris",
                     description='Lead single of the Chainsmoker\'s first '
                                 'album, Memories: Do Not Open. The song '
                                 'peaked at number 6 on the Billboard Hot '
                                 '100.',
                     category=category3)

session.add(music1)
session.commit()

print ("Added items to catalog!")
