from entities.entity_base import EntityBase
import re
from email.utils import parseaddr
import time
import logging

logger = logging.getLogger(__name__)


class Person(EntityBase):

    def __init__(self, name='', email=''):
        super(Person, self).__init__()
        self.name = name
        self.email = email
        self.last_updated = None

# TODO: remove redundancy in return_entity_obj

    @classmethod
    def return_entity_contributor(cls, name, email, id, last_updated):
        objcon = Contributor(name, email)
        objcon.id = id
        objcon.last_updated = last_updated
        return objcon

    def save(self):
        person_criteria = {'name': self.name, 'email': self.email}
        return super(Person, self).save(criteria_dict=person_criteria)

    @classmethod
    def return_entity_author(cls, name, email, id, last_updated):
        objauthor = Author(name, email)
        objauthor.id = id
        objauthor.last_updated = last_updated
        return objauthor

    @classmethod
    def find_by_criteria(cls, label, criteria_dict):
        values = super(Person, cls).find_by_criteria(label, criteria_dict)
        if values is None:
            return None
        if label == 'Author':
            return cls.return_entity_author(values.get('name')[0],
                            values.get('email')[0], values.get('id'), values.get('last_updated')[0])
        else:
            return cls.return_entity_contributor(values.get('name')[0],
                                 values.get('email')[0], values.get('id'), values.get('last_updated')[0])

    def create(self):
        try:
            person_criteria = {'name': self.name, 'email': self.email}
            present_person = Person.find_by_criteria(
                self.label, person_criteria)
            if present_person is None:
                ts = time.time()
                results = self.g().addV(self.label). \
                    property('vertex_label', self.label). \
                    property('name', self.name). \
                    property('email', self.email).\
                    property('last_updated', ts).\
                    toList()

                logger.debug("create() Person-->%s - results: %s" %
                             (self.label, results))

                self.last_updated = ts
                self.id = results[0].id
                logger.debug("Vertex ID : %s, Person-->%s: %s" %
                            (self.id, self.label, self))
                  
                logger.info("---Create--- %s ---NEW = %d"%(self.label, self.id))

                return self.id
            else:
                logger.debug("Person exists: %s " %
                             present_person.id)
                self.last_updated = present_person.last_updated
                self.id = present_person.id

                logger.info("---Create--- %s ---EXISTS = %d"%(self.label, self.id))
                
                return self.id

        except Exception as e:
            logger.error("create() failed: %s" % e)
            return None

    def update(self):
        try:
            ts = time.time()
            results = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('name', self.name). \
                property('email', self.email).\
                property('last_updated', ts).\
                toList()

            self.last_updated = ts
            logger.debug("update() Person-->%s - results: %s" %
                         (self.label, results))
            logger.debug("Vertex ID : %s, Person-->%s: %s" %
                        (self.id, self.label, self))

            logger.info("---Update--- %s = %d"%(self.label, self.id))
            
            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None


# TODO: Take care of inconsistency in person's name-email
class Author(Person):
    label = 'Author'

    def __init__(self, name='', email=''):
        super(Author, self).__init__(name, email)
        self.label = Author.label

    @classmethod
    def load_from_json(cls, authors_data):
        authors_list = []
        if 'details' in authors_data and len(authors_data["details"]) != 0:
            if 'author' in authors_data["details"][0] and authors_data["details"][0]["author"] is not None:
                authors = authors_data["details"][0]["author"]
                if type(authors) is not list:
                    authors = [authors]

                for a in authors:
                    (n, e) = parseaddr(a)
                    objauthor = Author(n, e)
                    authors_list.append(objauthor)
        return authors_list


class Contributor(Person):
    label = 'Contributor'

    def __init__(self, name='', email=''):
        super(Contributor, self).__init__(name, email)
        self.label = Contributor.label

    @classmethod
    def load_from_json(cls, contributors_data):
        contributors_list = []
        if 'details' in contributors_data and len(contributors_data["details"]) != 0:
            first_entry = contributors_data["details"][0]
            if 'contributors' in first_entry and first_entry["contributors"] is not None:
                contributors = first_entry["contributors"]
                if type(contributors) is not list:
                    contributors = [contributors]
                for c in contributors:
                    (n, e) = parseaddr(c)
                    objcontributor = Contributor(n, e)
                    contributors_list.append(objcontributor)
        return contributors_list
