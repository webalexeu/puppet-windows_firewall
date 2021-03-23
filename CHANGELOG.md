# Changelog

All notable changes to this project will be documented in this file.


## Release 1.0.1 (2021-03-23)

[Full Changelog](https://github.com/webalexeu/puppet-windows_firewall/compare/v1.0.0...v1.0.1)

**Features**

- Removing support for: 2008 Server/2008R2 Server/2012 Server/Windows 7

**Bugfixes**

- [Update of rule not working when using square brackets in the name](https://github.com/webalexeu/puppet-windows_firewall/issues/6)

**Known Issues**

## Release 1.0.0 (2021-03-22)

[Full Changelog](https://github.com/webalexeu/puppet-windows_firewall/compare/v0.2.0...v1.0.0)

**Features**

- Add update function for rules. Previously, in case of firewall rule parameters change, rule was deleted and created with new parameters, now rule is in-place updated (Only firewall rule name change will trigger a delete/create process)

**Bugfixes**

**Known Issues**

## Release 0.2.0 (2020-12-18)

[Full Changelog](https://github.com/webalexeu/puppet-windows_firewall/compare/v0.1.0...v0.2.0)

**Features**

- Listing of rules is now based on PowerShell (Previously netsh)

**Bugfixes**

**Known Issues**

## Release 0.1.0 (2020-12-17)

**Features**

- Initial Release (Forked from https://github.com/GeoffWilliams/puppet-windows_firewall)
- Add management of Connection Security Rules (IPsec)

**Bugfixes**

**Known Issues**
