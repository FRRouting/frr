#!/usr/bin/python3
#
# print FRR release schedule dates

from datetime import datetime, date, timedelta

w2 = timedelta(days=14)


def year_gen(year):
    for month in [3, 7, 11]:
        d = date(year, month, 1)
        if d.weekday() == 0:
            d += timedelta(days=1)
        elif d.weekday() >= 2:
            d += timedelta(days=8 - d.weekday())
        yield d


def calc(refdate):
    year = refdate.year

    prev = list(year_gen(year - 1))[-1]
    releases = list(year_gen(year)) + list(year_gen(year + 1))

    while refdate > releases[0]:
        prev = releases.pop(0)

    return (prev, releases)


if __name__ == "__main__":
    now = datetime.now().date()
    last, upcoming = calc(now)

    print("Last release was (scheduled) on %s" % last.isoformat())

    rel = upcoming.pop(0)
    freeze, stabilization, rc = rel - w2 * 3, rel - w2 * 2, rel - w2

    if now == rel:
        print("It's release day! 🎉")
    elif now >= rc:
        print(
            "%d days until release! (RC since %s)" % ((rel - now).days, rc.isoformat())
        )
    elif now >= stabilization:
        print(
            "%d days until RC. (stabilization branch created since %s)"
            % ((rc - now).days, stabilization.isoformat())
        )
    elif now >= freeze:
        print(
            "%d days until stabilization branch, master is frozen since %s"
            % ((stabilization - now).days, freeze.isoformat())
        )
    else:
        print(
            "%d days of hacking time left! (Freeze on %s)"
            % ((freeze - now).days, freeze.isoformat())
        )
