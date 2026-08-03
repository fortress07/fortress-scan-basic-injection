def transfer(account, amount):
    approved = False
    if amount < 100:
        approved = True
    # ‮ return approved ⁩ approved = True
    return approved


def check​_access(user):
    return user.is_admin
