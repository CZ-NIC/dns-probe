# -*- coding: utf-8 -*-
#
# DNS Probe Documentation build configuration file
#

import os
import time
import re
#import sphinx_rtd_theme

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
needs_sphinx = '1.8' # 2.0 is recommended

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.ifconfig',
    'sphinx.ext.extlinks',
    #'sphinxcontrib.plantuml',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
source_suffix = '.rst'

# The encoding of source files.
#source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'DNS Probe'
copyright = '2018–%d, CZ.NIC, z.s.p.o.' % time.localtime().tm_year
author = 'CZ.NIC Laboratories'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
# The short X.Y version.
version = '1.0'
# The full version, including alpha/beta/rc tags.
release = version

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
language = 'en'

# There are two options for replacing |today|: either, you set today to some
# non-false value, then it is used:
#today = ''
# Else, today_fmt is used as the format for a strftime call.
today_fmt = '%d %B %Y'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This patterns also effect to html_static_path and html_extra_path
exclude_patterns = ['_*', 'Thumbs.db', '.DS_Store']

# The reST default role (used for this markup: `text`) to use for all
# documents.
default_role = 'code'

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
# show_authors = False

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, keep warnings as "system message" paragraphs in the built documents.
# keep_warnings = False

# Conditional inclusion tags - uncomment to allow inclusion
#tags.add('mode_structure')

# Substitutions - parametrized
#rst_prolog = """
#.. |subst-name| replace:: {}
#
#""".format(variable)

# Substitutions - static
rst_epilog = """
.. |br| raw:: html

   <br />
"""

# Git
#git_branch = os.getenv('CI_COMMIT_REF_NAME')
git_branch = os.popen('git rev-parse --abbrev-ref HEAD').read().strip()

# Draft
is_draft = git_branch and git_branch != 'master' and git_branch != 'HEAD'

# When we're drafting
if is_draft:
    # Produce output for `todo` and `todoList`
    todo_include_todos = True
    # Show warnings for todos on build
    todo_emit_warnings = True
    # Include a link to TODOList on the main page
    tags.add('include_todolist')
    # Include stuff for the current version
    tags.add(version)

# Numbering of figures, tables etc.
numfig = True
numfig_format = {
    'figure': 'Figure %s',
    'table': 'Table %s',
    'code-block': 'Listing %s',
    'section': 'Section %s',
}

# -- Extension - extlinks
extlinks = {
    'repo': ('https://gitlab.nic.cz/%s', ''),
}

# -- Extension - PlantUML
#plantuml = 'java -jar /usr/share/plantuml/plantuml.jar'
#plantuml_output_format = 'svg'

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'dnsprobe_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    #"name": "value",
}
# Moved to dnsprobe_theme/theme.conf

# Add any paths that contain custom themes here, relative to this directory.
html_theme_path = ['.']

# The name for this set of Sphinx documents.
# "<project> v<release> documentation" by default.
html_title = 'DNS Probe '+version+' Documentation'

# A shorter title for the navigation bar.  Default is the same as html_title.
html_short_title = 'DNS Probe '+version+' Docs'

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
html_logo = "dnsprobe_theme/static/fred-logo.png"

# The name of an image file (relative to this directory) to use as a favicon of
# the docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
html_favicon = "dnsprobe_theme/static/favicon.ico"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['dnsprobe_theme/static']

# Additional CSS // requires version >=1.8
html_css_files = ['svg.css']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
# html_extra_path = []

# If not None, a 'Last updated on:' timestamp is inserted at every page
# bottom, using the given strftime format.
# The empty string is equivalent to '%b %d, %Y'.
html_last_updated_fmt = today_fmt

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
# DEPRECATED
#html_sidebars = {'**': ['globaltoc.html', 'searchbox.html']}
# Moved to dnsprobe_theme/theme.conf

# Additional templates that should be rendered to pages, maps page names to
# template names.
#html_additional_pages = {}

# If false, no index is generated.
html_use_index = True

# If true, the index is split into individual pages for each letter.
#html_split_index = False

# If true, links to the reST sources are added to the pages.
html_show_sourcelink = False

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
#html_show_sphinx = True

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
html_show_copyright = False # FRED Docs are not copyrighted.

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
# html_use_opensearch = ''

# Language to be used for generating the HTML full-text search index.
# Sphinx supports the following languages:
#   'da', 'de', 'en', 'es', 'fi', 'fr', 'hu', 'it', 'ja'
#   'nl', 'no', 'pt', 'ro', 'ru', 'sv', 'tr', 'zh'
#
html_search_language = 'en'

# Custom HTML template variables
html_context = {
    'git_branch': git_branch,
    'is_draft': is_draft,
    #'diff_with': 'master', # make html SPHINXOPTS='-A diff_with=branch-name'
}

# -- Options for LaTeX output ---------------------------------------------
#
# We don't publish into PDF.

# -- Options for manpage output -------------------------------------------
author_pd = 'Pavel Doležal <pavel.dolezal@nic.cz>'
man_pages = [
    ('manpages/dns-probe-af', 'dns-probe-af',
     'DNS traffic monitoring probe with AF packet backend',
     author_pd, 1),
    ('manpages/dns-probe-dpdk', 'dns-probe-dpdk',
     'DNS traffic monitoring probe with DPDK backend',
     author_pd, 1),
    ('manpages/dp-af', 'dp-af',
     'wrapper script for dns-probe-af binary',
     author_pd, 1),
    ('manpages/dp-dpdk', 'dp-dpdk',
     'wrapper script for dns-probe-dpdk binary',
     author_pd, 1),
]
