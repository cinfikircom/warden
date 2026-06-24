from django.db import models
class User(models.Model):
    email = models.EmailField()
    first_name = models.CharField(max_length=100)
    # NOT: yumusak silme alani bilincli olarak eklenmedi (regresyon fixture'i)
