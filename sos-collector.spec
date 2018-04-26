Summary: Capture sosreports from multiple nodes simultaneously
Name: sos-collector
Version: 1.0
Release: 1%{?dist}
Source0: http://people.redhat.com/jhunsake/sos-collector/releases/%{name}-%{version}.tar.gz
License: GPLv2
BuildArch: noarch
BuildRequires: python3-devel
BuildRequires: python3-paramiko
Url: https://github.com/sosreport/sos-collector
Requires: python3 >= 3.4
Requires: sos >= 3.0
Requires: python3-six
Requires: python3dist(paramiko) >= 2.0
Obsoletes: clustersos


%description
sos-collector is a utility designed to capture sosreports from multiple nodes 
at once and collect them into a single archive. If the nodes are part of 
a cluster, profiles can be used to configure how the sosreport command 
is run on the nodes.

%prep
%setup -q

%build
%py3_build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man1
mkdir -p ${RPM_BUILD_ROOT}%{license}
install -m444 ${RPM_BUILD_DIR}/%{name}-%{version}/LICENSE ${RPM_BUILD_ROOT}%{license}
install -m644 ${RPM_BUILD_DIR}/%{name}-%{version}/man/en/sos-collector.1 ${RPM_BUILD_ROOT}%{_mandir}/man1/
%py3_install



%check
%{__python3} setup.py test

%files
%{_bindir}/sos-collector
%{python3_sitelib}/*
%{_mandir}/man1/*

%license LICENSE

%changelog
* Thu Apr 26 2018 Jake Hunsaker <jhunsake@redhat.com> 1.0-1
  - Renamed project to sos-collector
  - Moved github repo to sosreport org
