This is a horribly dangerous tool, the only purpose of which is to actively
destroy the content of a LiveJournal account. I wrote it so I could remove
my content from LJ in protest at the April 2017 ToS change.

It's a Python script. I don't offer any support or warranty. You use it at your own risk.

It's a command-line script. You have to have Python 2.7 installed.

You have to explicitly tell the script what you want to do with your entries.
The options are:

* `--block-out` to replace all non-whitespace text with the unicode block character '█' (U+2588)
* `--random-garbage` to replace all non-whitespace text with randomly chosen letters and numbers
* `--mixed-mode` to randomly choose whether to block-out or random-garbage each entry in turn
* `--delete` to just delete the entry text, which has the effect of deleting the entry completely.
* `--printout` is a test mode which doesn't change anything.

Note that *all* the text of an entry is replaced, including any inline HTML-like tags such as `<lj-cut>`. 

Entry subjects are affected in the same way as the entry text. The posting
date, mood, userpic, entry tags and comments are left unchanged.

**NOTE:** If you are importing your content to another site, you should make
sure that that import has finished before you run this tool.

~~~~
usage: ljshred.py [-h] [--cleartext_password] [--except-latest]
                  [--start-date YYYY-MM-DD] [--end-date YYYY-MM-DD]
                  [--printout | --block-out | --random-garbage | --mixed-mode | --delete]

Shreds all the entries in a LiveJournal.

optional arguments:
  -h, --help            show this help message and exit
  --cleartext_password  Sends the password in (nearly) clear text, which is
                        faster but less secure
  --except-latest       Doesn't affect the latest entry
  --start-date YYYY-MM-DD
                        If given, starts shredding at the given date (e.g.
                        2017-12-31)
  --end-date YYYY-MM-DD
                        If given, stops shredding at the given date

Action modes (specify one):
  --printout            Only prints out all the entries it would touch,
                        doesn't actually change anything.
  --block-out           Replaces all non-whitespace text in all entries with a
                        solid block character
  --random-garbage      Replaces entries with random garbage text
  --mixed-mode          A mixture of --random-garbage and --block-out modes
  --delete              Deletes entries

This program is DANGEROUS and IRREVERSIBLE. Use at your own risk.
~~~~