(window.webpackJsonp=window.webpackJsonp||[]).push([[8],{100:function(e,t,n){"use strict";n.d(t,"a",(function(){return b})),n.d(t,"b",(function(){return d}));var r=n(0),a=n.n(r);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function c(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var p=a.a.createContext({}),s=function(e){var t=a.a.useContext(p),n=t;return e&&(n="function"==typeof e?e(t):c(c({},t),e)),n},b=function(e){var t=s(e.components);return a.a.createElement(p.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.a.createElement(a.a.Fragment,{},t)}},f=a.a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,o=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),b=s(n),f=r,d=b["".concat(o,".").concat(f)]||b[f]||u[f]||i;return n?a.a.createElement(d,c(c({ref:t},p),{},{components:n})):a.a.createElement(d,c({ref:t},p))}));function d(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,o=new Array(i);o[0]=f;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c.mdxType="string"==typeof e?e:r,o[1]=c;for(var p=2;p<i;p++)o[p]=n[p];return a.a.createElement.apply(null,o)}return a.a.createElement.apply(null,n)}f.displayName="MDXCreateElement"},64:function(e,t,n){"use strict";n.r(t),n.d(t,"frontMatter",(function(){return o})),n.d(t,"metadata",(function(){return c})),n.d(t,"rightToc",(function(){return l})),n.d(t,"default",(function(){return s}));var r=n(2),a=n(6),i=(n(0),n(100)),o={id:"intro",title:"Intro",sidebar_label:"Intro"},c={unversionedId:"pipeline/intro",id:"pipeline/intro",isDocsHomePage:!1,title:"Intro",description:"The NetSage Pipeline",source:"@site/docs/pipeline/intro.md",slug:"/pipeline/intro",permalink:"/netsage-pipeline/docs/next/pipeline/intro",editUrl:"https://github.com/netsage-project/netsage-pipeline/edit/master/website/docs/pipeline/intro.md",version:"current",sidebar_label:"Intro",sidebar:"Pipeline",next:{title:"Tstat",permalink:"/netsage-pipeline/docs/next/pipeline/tstat"}},l=[{value:"Components",id:"components",children:[]},{value:"Sensors and Data Collection",id:"sensors-and-data-collection",children:[{value:"Importer",id:"importer",children:[]}]}],p={rightToc:l};function s(e){var t=e.components,n=Object(a.a)(e,["components"]);return Object(i.b)("wrapper",Object(r.a)({},p,n,{components:t,mdxType:"MDXLayout"}),Object(i.b)("h1",{id:"the-netsage-pipeline"},"The NetSage Pipeline"),Object(i.b)("h1",{id:"description"},"Description"),Object(i.b)("p",null,"The Netsage Flow Processing Pipeline includes several components for processing network flow data, including importing, deidentification, metadata tagging, flow stitching, etc."),Object(i.b)("h2",{id:"components"},"Components"),Object(i.b)("p",null,"The Pipeline is made of the following components (Currently)"),Object(i.b)("ul",null,Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"https://github.com/netsage-project/netsage-pipeline/blob/master/lib/GRNOC/NetSage/Deidentifier/NetflowImporter.pm"}),"Importer"),"  (Collection of perl scripts)",Object(i.b)("ul",{parentName:"li"},Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"importer"}),"doc")))),Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"https://www.elastic.co/logstash"}),"Elastic Logstash")," Performs a variety of transformation on the data",Object(i.b)("ul",{parentName:"li"},Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"logstash"}),"doc")," "))),Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"https://www.rabbitmq.com/"}),"RabbitMQ")," used for message passing and queing of tasks.")),Object(i.b)("h2",{id:"sensors-and-data-collection"},"Sensors and Data Collection"),Object(i.b)("ul",null,Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"https://github.com/netsage-project/docker-nfdump-collector"}),"nfdump")," Utility used to capture Netflow/Sflow to disk",Object(i.b)("ul",{parentName:"li"},Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"nfdump"}),"doc")))),Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"https://github.com/netsage-project/tstat-transport"}),"tstat")," Utility used to capture read more on the ",Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"http://tstat.polito.it/"}),"official site"),Object(i.b)("ul",{parentName:"li"},Object(i.b)("li",{parentName:"ul"},Object(i.b)("a",Object(r.a)({parentName:"li"},{href:"tstat"}),"doc"))))),Object(i.b)("p",null,'"Testpoints" or "sensors" collect flow data (',Object(i.b)("a",Object(r.a)({parentName:"p"},{href:"http://tstat.polito.it/"}),"tstat"),", ",Object(i.b)("a",Object(r.a)({parentName:"p"},{href:"https://www.rfc-editor.org/info/rfc3176"}),"sflow"),", or ",Object(i.b)("a",Object(r.a)({parentName:"p"},{href:"https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-netflow/prod_white_paper0900aecd80406232.html"}),"netflow"),') and send it to a "pipeline host" for processing (for globanoc, flow-proc.bldc.grnoc.iu.edu or netsage-probe1.grnoc.iu.edu). '),Object(i.b)("p",null,"Tstat data goes directly into the netsage_deidentifier_raw queue rabbit queue. The other data is written to nfcapd files."),Object(i.b)("h3",{id:"importer"},Object(i.b)("a",Object(r.a)({parentName:"h3"},{href:"importer"}),"Importer")),Object(i.b)("p",null,"A netsage-netflow-importer-daemon reads any new nfcapd files that have come in after a configurable delay. The importer aggregates flows within each file, and writes the results to the netsage_deidentifier_raw queue rabbit queue."))}s.isMDXComponent=!0}}]);