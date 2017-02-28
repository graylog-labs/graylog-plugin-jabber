XMPP / Jabber Plugin for Graylog
================================

[![Build Status](https://travis-ci.org/Graylog2/graylog-plugin-jabber.svg?branch=master)](https://travis-ci.org/Graylog2/graylog-plugin-jabber)

XMPP/Jabber Alarmcallback Plugin for Graylog.

**Required Graylog version:** 2.2.0 and later

## Installation

[Download the plugin](https://github.com/Graylog2/graylog-plugin-jabber/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Build

This project is using Maven 3 and requires Java 8 or higher.

You can build a plugin (JAR) with `mvn package`.

DEB and RPM packages can be build with `mvn jdeb:jdeb` and `mvn rpm:rpm` respectively.

## Plugin Release

We are using the maven release plugin:

```
$ mvn release:prepare
[...]
$ mvn release:perform
```

This sets the version numbers, creates a tag and pushes to GitHub. Travis CI will build the release artifacts and upload to GitHub automatically.

## License

Copyright (c) 2014-2017 Graylog, Inc.

This library is licensed under the GNU General Public License, Version 3.0.

See https://www.gnu.org/licenses/gpl-3.0.html or the LICENSE.txt file in this repository for the full license text.
