#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sqlite3


def GetHashes(db, vers):
    w = '%v{}%'.format(vers)

    return db.execute('''
        SELECT fullhash
        FROM Responder
        WHERE
          type LIKE ?
        AND
          UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)
    ''', (w,)).fetchall()


db = sqlite3.connect("./Responder.db")

for v in [1, 2]:
    print('Dumping NTLMv{} hashes:'.format(v))

    h = GetHashes(db, v)
    s = '\n'.join(h)

    with open('DumpNTLMv{}.txt'.format(v), 'w') as fp:
        fp.write(s + '\n')

    print(s)
