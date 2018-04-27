Summary: Capture sosreports from multiple nodes simultaneously
Name: sos-collector
Version: 1.0
Release: 1%{?dist}
Source0: http://people.redhat.com/jhunsake/sos-collector/releases/%{name}-%{version}.tar.gz
License: GPLv2
BuildArch: noarch
Url: https://github.com/sosreport/sos-collector
Requires: sos >= 3.0
Obsoletes: clustersos < 1.2.2-2
Provides: clustersos = %{version}-%{release}

%?python_enable_dependency_generator

%if 0%{?rhel}
BuildRequires: python-devel
BuildRequires: python-paramiko
%else
BuildRequires: python3-devel
BuildRequires: python3-paramiko
%endif


%description
sos-collector is a utility designed to capture sosreports from multiple nodes 
at once and collect them into a single archive. If the nodes are part of 
a cluster, profiles can be used to configure how the sosreport command 
is run on the nodes.

%prep
%setup -q

%build
%if 0%{?rhel}
%py2_build
%else
%py3_build
%endif

%install
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man1
install -p -m644 man/en/sos-collector.1 ${RPM_BUILD_ROOT}%{_mandir}/man1/
%if 0%{?rhel}
%py2_install
%else
%py3_install
%endif



%check
%if 0%{?rhel}
%{__python2} setup.py test
%else
%{__python3} setup.py test
%endif

%files
%{_bindir}/sos-collector
%if 0%{?rhel}
%{python2_sitelib}/*
%else
%{python3_sitelib}/*
%endif
%{_mandir}/man1/*

%license LICENSE

%changelog
* Thu Apr 26 2018 Jake Hunsaker <jhunsake@redhat.com> 1.0-1
  - Renamed project to sos-collector
  - Moved github repo to sosreport org
