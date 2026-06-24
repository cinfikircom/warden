def store_card(db, card_number, cvv):
    db.insert(card_number=card_number, cvv=cvv)
