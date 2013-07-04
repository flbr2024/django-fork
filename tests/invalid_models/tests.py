import copy
import sys
import unittest

from django.core.checks import Error
from django.core.management.validation import get_validation_errors
from django.db import connection, models
from django.db.models.loading import cache, load_app
from django.test import TestCase
from django.test.utils import override_settings
from django.utils.six import StringIO


class InvalidModelTestCase(TestCase):
    """Import an appliation with invalid models and test the exceptions."""

    def setUp(self):
        # Make sure sys.stdout is not a tty so that we get errors without
        # coloring attached (makes matching the results easier). We restore
        # sys.stderr afterwards.
        self.old_stdout = sys.stdout
        self.stdout = StringIO()
        sys.stdout = self.stdout

        # This test adds dummy applications to the app cache. These
        # need to be removed in order to prevent bad interactions
        # with the flush operation in other tests.
        self.old_app_models = copy.deepcopy(cache.app_models)
        self.old_app_store = copy.deepcopy(cache.app_store)

    def tearDown(self):
        cache.app_models = self.old_app_models
        cache.app_store = self.old_app_store
        cache._get_models_cache = {}
        sys.stdout = self.old_stdout

    # Technically, this isn't an override -- TEST_SWAPPED_MODEL must be
    # set to *something* in order for the test to work. However, it's
    # easier to set this up as an override than to require every developer
    # to specify a value in their test settings.
    @override_settings(
        TEST_SWAPPED_MODEL='old_invalid_models.ReplacementModel',
        TEST_SWAPPED_MODEL_BAD_VALUE='not-a-model',
        TEST_SWAPPED_MODEL_BAD_MODEL='not_an_app.Target',
    )
    def test_invalid_models(self):
        try:
            module = load_app("invalid_models.old_invalid_models")
        except Exception:
            self.fail('Unable to load old_invalid_models module')

        get_validation_errors(self.stdout, module)
        self.stdout.seek(0)
        error_log = self.stdout.read()
        actual = error_log.split('\n')
        expected = module.model_errors.split('\n')

        unexpected = [err for err in actual if err not in expected]
        missing = [err for err in expected if err not in actual]
        self.assertFalse(unexpected, "Unexpected Errors: " + '\n'.join(unexpected))
        self.assertFalse(missing, "Missing Errors: " + '\n'.join(missing))


class CharFieldTests(TestCase):

    def test_missing_max_length_argument(self):
        field = models.CharField()
        errors = field.check()
        self.assertEqual(errors, [
            Error('No "max_length" argument.\n'
                'CharFields require "max_length" argument that is '
                'the maximum length (in characters) of the field.',
                hint='Set "max_length" argument.',
                obj=field),
        ])

    def test_negative_max_length(self):
        field = models.CharField(max_length=-1)
        errors = field.check()
        self.assertEqual(errors, [
            Error('Invalid "max_length" value.\n'
                'CharFields require a "max_length" attribute that is '
                'the maximum length (in characters) of the field '
                'and is a positive integer.',
                hint='Change "max_length" value to a positive integer.',
                obj=field),
        ])

    def test_bad_value_of_max_length(self):
        field = models.CharField(max_length="bad")
        errors = field.check()
        self.assertEqual(errors, [
            Error('Invalid "max_length" value.\n'
                'CharFields require a "max_length" attribute that is '
                'the maximum length (in characters) of the field '
                'and is a positive integer.',
                hint='Change "max_length" value to a positive integer.',
                obj=field),
        ])

    def test_non_iterable_choices(self):
        field = models.CharField(max_length=10, choices='bad')
        errors = field.check()
        self.assertEqual(errors, [
            Error('"choices" is not an iterable (e.g., a tuple or list).\n'
                '"choices" should be an iterable of pairs. The first element '
                'in each pair is the actual value to be stored, and '
                'the second element is the human-readable name. '
                'An example of a valid value is '
                '[("1", "first choice"), ("2", "second choice")].',
                hint='Convert "choices" into a list of pairs.',
                obj=field),
        ])

    def test_choices_containing_non_pairs(self):
        field = models.CharField(max_length=10, choices=[(1, 2, 3), (1, 2, 3)])
        errors = field.check()
        self.assertEqual(errors, [
            Error('Some items of "choices" are not pairs.\n'
                '"choices" should be an iterable of pairs. The first element '
                'in each pair is the actual value to be stored, and '
                'the second element is the human-readable name. '
                'An example of a valid value is '
                '[("1", "first choice"), ("2", "second choice")].',
                hint='Convert "choices" into a list of pairs.',
                obj=field),
        ])

    def test_bad_value_of_db_index(self):
        field = models.CharField(max_length=10, db_index='bad')
        errors = field.check()
        self.assertEqual(errors, [
            Error('Invalid "db_index" value (should be None, True or False).\n'
                'If set to True, a database index will be created for this '
                'field. ',
                hint='Set "db_index" to False or True '
                'or remove this argument.',
                obj=field),
        ])


class DecimalFieldTests(TestCase):

    def test_required_attributes(self):
        field = models.DecimalField()
        errors = field.check()
        self.assertEqual(errors, [
            Error('No "decimal_places" attribute.\n'
                'DecimalFields require a "decimal_places" attribute that is '
                'the number of decimal places to store with the number and is '
                'a non-negative integer smaller or equal to "max_digits". '
                'For example, if you set "decimal_places" to 2 then 1.23456 '
                'will be saved as 1.23.',
                hint='Set "decimal_places" argument.',
                obj=field),
            Error('No "max_digits" attribute.\n'
                'DecimalFields require a "max_digits" attribute that is '
                'the maximum number of digits allowed in the number and '
                'is a positive integer greater or equal to "decimal_places". '
                'For example, if you set "max_digits" to 5 and '
                '"decimal_places" to 2 then 999.99 is the greatest number '
                'that you can save.',
                hint='Set "max_length" argument.',
                obj=field),
        ])

    def test_negative_max_digits_and_decimal_places(self):
        field = models.DecimalField(max_digits=-1, decimal_places=-1)
        errors = field.check()
        self.assertEqual(errors, [
            Error('Invalid "decimal_places" value.\n'
                'DecimalFields require a "decimal_places" attribute that is '
                'the number of decimal places to store with the number and is '
                'a non-negative integer smaller or equal to "max_digits". '
                'For example, if you set "decimal_places" to 2 then 1.23456 '
                'will be saved as 1.23.',
                hint='Change "decimal_places" argument.',
                obj=field),
            Error('Invalid "max_digits" value.\n'
                'DecimalFields require a "max_digits" attribute that is '
                'the maximum number of digits allowed in the number and '
                'is a positive integer greater or equal to "decimal_places". '
                'For example, if you set "max_digits" to 5 '
                'and "decimal_places" to 2 then 999.99 is the greatest number '
                'that you can save.',
                hint='Change "max_length" argument.',
                obj=field),
        ])

    def test_bad_values_of_max_digits_and_decimal_places(self):
        field = models.DecimalField(max_digits="bad", decimal_places="bad")
        errors = field.check()
        self.assertEqual(errors, [
            Error('Invalid "decimal_places" value.\n'
                'DecimalFields require a "decimal_places" attribute that is '
                'the number of decimal places to store with the number and is '
                'a non-negative integer smaller or equal to "max_digits". '
                'For example, if you set "decimal_places" to 2 then 1.23456 '
                'will be saved as 1.23.',
                hint='Change "decimal_places" argument.',
                obj=field),
            Error('Invalid "max_digits" value.\n'
                'DecimalFields require a "max_digits" attribute that is '
                'the maximum number of digits allowed in the number and '
                'is a positive integer greater or equal to "decimal_places". '
                'For example, if you set "max_digits" to 5 and '
                '"decimal_places" to 2 then 999.99 is the greatest number '
                'that you can save.',
                hint='Change "max_length" argument.',
                obj=field),
        ])

    def test_decimal_places_greater_than_max_digits(self):
        field = models.DecimalField(max_digits=9, decimal_places=10)
        errors = field.check()
        self.assertEqual(errors, [
            Error('"max_digits" smaller than "decimal_places".\n'
                'DecimalFields require a "max_digits" argument that is '
                'the maximum number of digits allowed in the number and '
                'is a positive integer greater or equal to "decimal_places". '
                'For example, if you set "decimal_places" to 2 and you '
                'want to store numbers up to 999.99 then you should set '
                '"max_digits" to 5.',
                hint='Increase "max_digits" value to at least '
                '"decimal_places" value.',
                obj=field),
        ])

    def test_valid_field(self):
        field = models.DecimalField(max_digits=10, decimal_places=10)
        self.assertEqual(field.check(), [])


class RelativeFieldTests(TestCase):

    def setUp(self):
        # If you create a model in a test, the model is accessible in other
        # tests. To avoid this, we need to clear list of all models created in
        # `invalid_models` module.
        cache.app_models['invalid_models'] = {}
        cache._get_models_cache = {}

    def test_foreign_key_to_missing_model(self):
        # Model names are resolved when a model is being created, so we cannot
        # test relative fields in isolation and we need to attach them to a
        # model.
        class Model(models.Model):
            foreign_key = models.ForeignKey('Rel1')

        field = Model.foreign_key.field
        errors = field.check()
        self.assertEqual(errors, [
            Error('No Rel1 model or it is an abstract model.\n'
                'The field has a relation with model Rel1, which '
                'has either not been installed or is abstract.',
                hint='Ensure that you did not misspell the model name and '
                'the model is not abstract. Does your INSTALLED_APPS setting '
                'contain the app where Rel1 is defined?',
                obj=field),
        ])

    def test_many_to_many_to_missing_model(self):
        class Model(models.Model):
            m2m = models.ManyToManyField("Rel2")

        field = Model.m2m.field
        errors = field.check(from_model=Model)
        self.assertEqual(errors, [
            Error('No Rel2 model or it is an abstract model.\n'
                'The field has a many to many relation with model Rel2, '
                'which has either not been installed or is abstract.',
                hint='Ensure that you did not misspell the model name and '
                'the model is not abstract. Does your INSTALLED_APPS setting '
                'contain the app where Rel2 is defined?',
                obj=field),
        ])

    def test_ambiguous_relationship_model(self):

        class Person(models.Model):
            pass

        class Group(models.Model):
            field = models.ManyToManyField('Person',
                through="AmbiguousRelationship", related_name='tertiary')

        class AmbiguousRelationship(models.Model):
            # Too much foreign keys to Person.
            first_person = models.ForeignKey(Person, related_name="first")
            second_person = models.ForeignKey(Person, related_name="second")
            second_model = models.ForeignKey(Group)

        field = Group.field.field
        errors = field.check(from_model=Group)
        self.assertEqual(errors, [
            Error('More than one foreign key to Person in intermediary '
                'AmbiguousRelationship model.\n'
                'AmbiguousRelationship has more than one foreign key '
                'to Person, which is ambiguous and is not permitted.',
                hint='If you want to create a recursive relationship, use '
                'ForeignKey("self", symmetrical=False, '
                'through="AmbiguousRelationship").',
                obj=field),
        ])

    def test_relationship_model_with_foreign_key_to_wrong_model(self):
        class WrongModel(models.Model):
            pass

        class Person(models.Model):
            pass

        class Group(models.Model):
            members = models.ManyToManyField('Person',
                through="InvalidRelationship")

        class InvalidRelationship(models.Model):
            person = models.ForeignKey(Person)
            wrong_foreign_key = models.ForeignKey(WrongModel)
            # The last foreign key should point to Group model.

        field = Group.members.field
        errors = field.check(from_model=Group)
        self.assertEqual(errors, [
            Error('No foreign key to Group or Person '
                'in intermediary InvalidRelationship model.\n'
                'The field is a manually-defined many to many relation '
                'through model InvalidRelationship, which does not have '
                'foreign keys to Group or Person.\n',
                hint='Ensure that there are foreign keys to Group '
                'and Person models in InvalidRelationship model.',
                obj=field),
        ])

    def test_relationship_model_missing_foreign_key(self):
        class Person(models.Model):
            pass

        class Group(models.Model):
            members = models.ManyToManyField('Person',
                through="InvalidRelationship")

        class InvalidRelationship(models.Model):
            group = models.ForeignKey(Group)
            # No foreign key to Person

        field = Group.members.field
        errors = field.check(from_model=Group)
        self.assertEqual(errors, [
            Error('No foreign key to Group or Person '
                'in intermediary InvalidRelationship model.\n'
                'The field is a manually-defined many to many relation '
                'through model InvalidRelationship, which does not have '
                'foreign keys to Group or Person.\n',
                hint='Ensure that there are foreign keys to Group '
                'and Person models in InvalidRelationship model.',
                obj=field),
        ])

    def test_missing_relationship_model(self):
        class Person(models.Model):
            pass

        class Group(models.Model):
            members = models.ManyToManyField('Person',
                through="MissingM2MModel")

        field = Group.members.field
        errors = field.check(from_model=Group)
        self.assertEqual(errors, [
            Error('No intermediary model MissingM2MModel.\n'
                'The field specifies a many-to-many relation through model '
                'MissingM2MModel, which has not been installed.',
                hint='Ensure that you did not misspell the model name and '
                'the model is not abstract. Does your INSTALLED_APPS setting '
                'contain the app where MissingM2MModel is defined?',
                obj=field),
        ])

    def test_symmetrical_self_referential_field(self):
        class Person(models.Model):
            # Implicit symmetrical=False.
            friends = models.ManyToManyField('self', through="Relationship")

        class Relationship(models.Model):
            first = models.ForeignKey(Person, related_name="rel_from_set")
            second = models.ForeignKey(Person, related_name="rel_to_set")

        field = Person.friends.field
        errors = field.check(from_model=Person)
        self.assertEqual(errors, [
            Error('Symmetrical m2m field with intermediate table.\n'
                'Many-to-many fields with intermediate tables cannot '
                'be symmetrical.',
                hint='Set symmetrical=False on the field.',
                obj=field),
        ])

    def test_too_many_foreign_keys_in_self_referential_model(self):
        class Person(models.Model):
            friends = models.ManyToManyField('self',
                through="InvalidRelationship", symmetrical=False)

        class InvalidRelationship(models.Model):
            first = models.ForeignKey(Person, related_name="rel_from_set_2")
            second = models.ForeignKey(Person, related_name="rel_to_set_2")
            third = models.ForeignKey(Person, related_name="too_many_by_far")

        field = Person.friends.field
        errors = field.check(from_model=Person)
        self.assertEqual(errors, [
            Error('More than two foreign keys to Person '
                'in intermediary model InvalidRelationship.\n'
                'InvalidRelationship has more than two foreign keys to '
                'Person, which is ambiguous and is not permitted.',
                hint='Remove excessive foreign keys to Person '
                'in InvalidRelationship.',
                obj=field),
        ])

    def test_symmetric_self_reference_with_intermediate_table(self):
        class Person(models.Model):
            # Explicit symmetrical=True.
            friends = models.ManyToManyField('self',
                through="Relationship", symmetrical=True)

        class Relationship(models.Model):
            first = models.ForeignKey(Person, related_name="rel_from_set")
            second = models.ForeignKey(Person, related_name="rel_to_set")

        field = Person.friends.field
        errors = field.check(from_model=Person)
        self.assertEqual(errors, [
            Error('Symmetrical m2m field with intermediate table.\n'
                'Many-to-many fields with intermediate tables cannot '
                'be symmetrical.',
                hint='Set symmetrical=False on the field.',
                obj=field),
        ])

    def test_foreign_key_to_abstract_model(self):
        class Model(models.Model):
            foreign_key = models.ForeignKey('AbstractModel')

        class AbstractModel(models.Model):
            class Meta:
                abstract = True

        field = Model.foreign_key.field
        errors = field.check()
        self.assertEqual(errors, [
            Error('No AbstractModel model or it is an abstract model.\n'
                'The field has a relation with model AbstractModel, which '
                'has either not been installed or is abstract.',
                hint='Ensure that you did not misspell the model name and '
                'the model is not abstract. Does your INSTALLED_APPS setting '
                'contain the app where AbstractModel is defined?',
                obj=field),
        ])

    def test_m2m_to_abstract_model(self):
        class AbstractModel(models.Model):
            class Meta:
                abstract = True

        class Model(models.Model):
            m2m = models.ManyToManyField('AbstractModel')

        field = Model.m2m.field
        errors = field.check(from_model=Model)
        self.assertEqual(errors, [
            Error('No AbstractModel model or it is an abstract model.\n'
                'The field has a many to many relation with model '
                'AbstractModel, which has either not been installed '
                'or is abstract.',
                hint='Ensure that you did not misspell the model name and '
                'the model is not abstract. Does your INSTALLED_APPS setting '
                'contain the app where AbstractModel is defined?',
                obj=field),
        ])

    def test_unique_m2m(self):
        class Person(models.Model):
            name = models.CharField(max_length=5)

        class Group(models.Model):
            members = models.ManyToManyField('Person', unique=True)

        field = Group.members.field
        errors = field.check(from_model=Group)
        self.assertEqual(errors, [
            Error('Unique m2m field.\n'
                'ManyToManyFields cannot be unique.',
                hint='Remove the "unique" argument on the field.',
                obj=field),
        ])

    def test_foreign_key_to_non_unique_field(self):
        class Target(models.Model):
            bad = models.IntegerField() # No unique=True

        class Model(models.Model):
            foreign_key = models.ForeignKey('Target', to_field='bad')

        field = Model.foreign_key.field
        errors = field.check()
        self.assertEqual(errors, [
            Error('No unique=True constraint on field "bad" under model '
                'Target.\n'
                'The field "bad" has to be unique because a foreign key '
                'references to it.',
                hint='Set unique=True argument on the field "bad" '
                'under model Target.',
                obj=field),
        ])

    def test_foreign_key_to_non_unique_field_under_explicit_model(self):
        class Target(models.Model):
            bad = models.IntegerField()

        # We don't need to attach the field to a model, because we pass Target
        # model explicitly.
        field = models.ForeignKey(Target, to_field='bad')
        errors = field.check()
        self.assertEqual(errors, [
            Error('No unique=True constraint on field "bad" under model '
                'Target.\n'
                'The field "bad" has to be unique because a foreign key '
                'references to it.',
                hint='Set unique=True argument on the field "bad" '
                'under model Target.',
                obj=field),
        ])

    def test_on_delete_set_null_on_non_nullable_field(self):
        class Person(models.Model):
            pass

        class Model(models.Model):
            foreign_key = models.ForeignKey('Person',
                on_delete=models.SET_NULL)

        field = Model.foreign_key.field
        errors = field.check()
        self.assertEqual(errors, [
            Error('on_delete=SET_NULL but null forbidden.\n'
                'The field specifies on_delete=SET_NULL, but cannot be null.',
                hint='Set null=True argument on the field.',
                obj=field),
        ])

    def test_on_delete_set_default_without_default_value(self):
        class Person(models.Model):
            pass

        class Model(models.Model):
            foreign_key = models.ForeignKey('Person',
                on_delete=models.SET_DEFAULT)

        field = Model.foreign_key.field
        errors = field.check()
        self.assertEqual(errors, [
            Error('on_delete=SET_DEFAULT but no default value.\n'
                'The field specifies on_delete=SET_DEFAULT, but has '
                'no default value.',
                hint='Set "default" argument on the field.',
                obj=field),
        ])

    def test_nullable_primary_key(self):
        field = models.IntegerField(primary_key=True, null=True)
        errors = field.check()
        if connection.features.interprets_empty_strings_as_nulls:
            self.assertEqual(errors, [])
        else:
            self.assertEqual(errors, [
                Error('null=True for primary_key.\n'
                    'Primary key fields cannot have null=True.',
                    hint='Set null=False on the field or '
                    'remove primary_key=True argument.',
                    obj=field),
            ])


class OtherFieldTests(TestCase):

    def test_missing_upload_to(self):
        field = models.FileField()
        errors = field.check()
        self.assertEqual(errors, [
            Error('No "upload_to" attribute.\n'
                'FileFields require an "upload_to" attribute.',
                hint='Set "upload_to" attribute.',
                obj=field),
        ])

    def test_nullable_boolean_field(self):
        field = models.BooleanField(null=True)
        errors = field.check()
        self.assertEqual(errors, [
            Error('null=True for BooleanField.\n'
                'BooleanFields do not accept null values. Use '
                'a NullBooleanField instead.',
                hint='Replace BooleanField with NullBooleanField.',
                obj=field),
        ])

    def test_non_nullable_blank_GenericIPAddressField(self):
        field = models.GenericIPAddressField(null=False, blank=True)
        errors = field.check()
        self.assertEqual(errors, [
            Error('null=False and blank=True for GenericIPAddressField.\n'
                'GenericIPAddressField cannot accept blank values '
                'if null values are not allowed, as blank values are stored '
                'as null.',
                hint='Allow to store null values (null=True) or '
                'forbid blank values (blank=False).',
                obj=field),
        ])
