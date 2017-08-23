# -*- coding: utf-8 -*-

##
# framework.knowledge
#
#  Copyright 2017 by Matthieu Daumas <matthieu@daumas.me> and other authors.
#
# This file is a part of fuddly, as part of the knowledge component.
#
#  Licensed under GNU General Public License 3.0 or later.
#  Some rights reserved. See COPYING, AUTHORS.
#
# @license GPL-3.0+ <http://spdx.org/licenses/GPL-3.0+>
##

import unittest

import framework.knowledge as kn
import framework.knowledge.all # !! kn.error.state.quiet = True !!

kn.error.state.quiet = False # (to avoid breaking other tests)

def build_weather_labels():
    w = kn.refine.label(name='weather', size=6)
    w.add(label='warm', value=[True, False])
    w.add(label='cold', value=[False, True], where=slice(0, 2))
    w.add(label='temp', where=slice(0, 2))

    w.add(label='rainy')
    w.add(label='cloudly')
    w.add(label='windy')

    w.add(label='!thunder', value=False)
    w.add(label='thunder', value=[True, None, True], where=slice(3, 6))

    w.add(label='rainstorm', where=slice(1, 4))
    w.add(label='thunderstorm', where=slice(2, 6))
    return kn.table.translation(w)


weather_labels = build_weather_labels()

# TOFIX: restructure tests code in a unittest-friendly fashion
class test_weather(unittest.TestCase):

    # run tests
    def test_weather(self):
        kn.error.state.quiet = True

        o = kn.oracle.oracle(kn.backends.naive_oracle)
        o.add_labels(weather_labels)

        o.submit('cold')
        self.assertTrue('cold' in o.query('cold'))

        o.submit('rainy')
        self.assertTrue('rainy' in o.query('rainstorm'))
        self.assertTrue('rainstorm' not in o.query('rainstorm'))

        o.submit('cloudly')
        self.assertTrue('rainstorm' in o.query('rainstorm'))
        self.assertTrue('thunderstorm' not in o.query('rainstorm'))
        self.assertTrue('thunderstorm' not in o.query('thunderstorm'))

        o.submit('windy')
        self.assertTrue('thunderstorm' not in o.query('rainstorm'))
        self.assertTrue('thunderstorm' in o.query('thunderstorm'))

        kn.error.state.quiet = False

if __name__ == '__main__':
    unittest.main()
