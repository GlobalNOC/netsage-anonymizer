(window.webpackJsonp=window.webpackJsonp||[]).push([[13],{102:function(e,t,n){"use strict";n.d(t,"a",(function(){return d})),n.d(t,"b",(function(){return m}));var o=n(0),r=n.n(o);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);t&&(o=o.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,o)}return n}function c(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,o,r=function(e,t){if(null==e)return{};var n,o,r={},a=Object.keys(e);for(o=0;o<a.length;o++)n=a[o],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(o=0;o<a.length;o++)n=a[o],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var l=r.a.createContext({}),u=function(e){var t=r.a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):c(c({},t),e)),n},d=function(e){var t=u(e.components);return r.a.createElement(l.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.a.createElement(r.a.Fragment,{},t)}},f=r.a.forwardRef((function(e,t){var n=e.components,o=e.mdxType,a=e.originalType,i=e.parentName,l=s(e,["components","mdxType","originalType","parentName"]),d=u(n),f=o,m=d["".concat(i,".").concat(f)]||d[f]||p[f]||a;return n?r.a.createElement(m,c(c({ref:t},l),{},{components:n})):r.a.createElement(m,c({ref:t},l))}));function m(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=n.length,i=new Array(a);i[0]=f;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c.mdxType="string"==typeof e?e:o,i[1]=c;for(var l=2;l<a;l++)i[l]=n[l];return r.a.createElement.apply(null,i)}return r.a.createElement.apply(null,n)}f.displayName="MDXCreateElement"},69:function(e,t,n){"use strict";n.r(t),n.d(t,"frontMatter",(function(){return i})),n.d(t,"metadata",(function(){return c})),n.d(t,"rightToc",(function(){return s})),n.d(t,"default",(function(){return u}));var o=n(2),r=n(6),a=(n(0),n(102)),i={},c={unversionedId:"components/docker_env",id:"components/docker_env",isDocsHomePage:!1,title:"docker_env",description:"Please make a copy of the .env and refer back to the docker dev guide on details on configuring the env. Most of the default value should work just fine.",source:"@site/docs/components/docker_env.md",slug:"/components/docker_env",permalink:"/netsage-pipeline/docs/next/components/docker_env",editUrl:"https://github.com/netsage-project/netsage-pipeline/edit/master/website/docs/components/docker_env.md",version:"current"},s=[{value:"inactivity_timeout",id:"inactivity_timeout",children:[]}],l={rightToc:s};function u(e){var t=e.components,n=Object(r.a)(e,["components"]);return Object(a.b)("wrapper",Object(o.a)({},l,n,{components:t,mdxType:"MDXLayout"}),Object(a.b)("p",null,"Please make a copy of the .env and refer back to the docker ",Object(a.b)("a",Object(o.a)({parentName:"p"},{href:"../devel/docker"}),"dev guide")," on details on configuring the env. Most of the default value should work just fine."),Object(a.b)("p",null,"The only major change you should be aware of are the following values. The output host defines where the final data will land. The sensorName defines what the data will be labeled as."),Object(a.b)("p",null,"If you don't send a sensor name it'll use the default docker hostname which changes each time you run the pipeline."),Object(a.b)("pre",null,Object(a.b)("code",Object(o.a)({parentName:"pre"},{className:"language-ini"}),"rabbitmq_output_host=rabbit\nrabbitmq_output_username=guest\nrabbitmq_output_pw=guest\nrabbitmq_output_key=netsage_archive_input\n\nsflowSensorName=sflowSensorName\nnetflowSensorName=netflowSensorName\n\n## Optional configurations\n## Not required, but these are exposed if you wish to use a different\n## value \naggregation_maps_path=/data/logstash-aggregation-maps ## this is configurable, but /data is required.  \ninactivity_timeout=630 ##  See below\nmax_flow_timeout=86400 ## cut off flows that are longer the N seconds.  Default is 24 hours\n")),Object(a.b)("p",null,"Please note, the default is to have one netflow collector and one sflow collector. If you need more collectors or do no need netflow or sflow simply comment out the collector you wish to ignore.  If you are following the advanced guide, you'll naturally have a more complex setup for each additional collector you've configured."),Object(a.b)("h3",{id:"inactivity_timeout"},"inactivity_timeout"),Object(a.b)("div",{className:"admonition admonition-note alert alert--secondary"},Object(a.b)("div",Object(o.a)({parentName:"div"},{className:"admonition-heading"}),Object(a.b)("h5",{parentName:"div"},Object(a.b)("span",Object(o.a)({parentName:"h5"},{className:"admonition-icon"}),Object(a.b)("svg",Object(o.a)({parentName:"span"},{xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"}),Object(a.b)("path",Object(o.a)({parentName:"svg"},{fillRule:"evenodd",d:"M6.3 5.69a.942.942 0 0 1-.28-.7c0-.28.09-.52.28-.7.19-.18.42-.28.7-.28.28 0 .52.09.7.28.18.19.28.42.28.7 0 .28-.09.52-.28.7a1 1 0 0 1-.7.3c-.28 0-.52-.11-.7-.3zM8 7.99c-.02-.25-.11-.48-.31-.69-.2-.19-.42-.3-.69-.31H6c-.27.02-.48.13-.69.31-.2.2-.3.44-.31.69h1v3c.02.27.11.5.31.69.2.2.42.31.69.31h1c.27 0 .48-.11.69-.31.2-.19.3-.42.31-.69H8V7.98v.01zM7 2.3c-3.14 0-5.7 2.54-5.7 5.68 0 3.14 2.56 5.7 5.7 5.7s5.7-2.55 5.7-5.7c0-3.15-2.56-5.69-5.7-5.69v.01zM7 .98c3.86 0 7 3.14 7 7s-3.14 7-7 7-7-3.12-7-7 3.14-7 7-7z"})))),"note")),Object(a.b)("div",Object(o.a)({parentName:"div"},{className:"admonition-content"}),Object(a.b)("p",{parentName:"div"},"If more than inactivity_timeout seconds have passed between the 'start' of this event and the 'start'\nof the LAST matching event, OR if no matching flow has coming in for inactivity_timeout seconds\non the clock, assume the flow has ended.\nUse 630 sec = 10.5 min for 5-min files,  960 sec = 16 min for AMPATH which has has 15-min files.\n(For 5-min files, this allows one 5 min gap or period during which the no. of bits transferred don't meet the cutoff)"))))}u.isMDXComponent=!0}}]);