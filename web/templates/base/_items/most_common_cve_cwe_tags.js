{
  const colors = [
  {% for cve in most_common_cve %}
  '#7E57C2',
  {% endfor %}
  ];

  const options = {
  series: [{
    name: 'CVE IDs',
    data: [{% for cve in most_common_cve %}
      {{cve.nused}},
      {% endfor %}]
    }],
    chart: {
      height: 350,
      type: 'bar',
      events: {
        click: function(chart, w, e) {
          // console.log(chart, w, e)
        }
      }
    },
    colors: colors,
    plotOptions: {
      bar: {
        columnWidth: '45%',
        distributed: true,
      }
    },
    dataLabels: {
      enabled: false
    },
    legend: {
      show: false
    },
    xaxis: {
      categories: [
        {% for cve in most_common_cve %}
        '{{cve.name}}',
        {% endfor %}
      ],
      labels: {
        style: {
          colors: colors,
          fontSize: '12px'
        }
      }
    }
  };

  const chart = new ApexCharts(document.querySelector("#most_common_cve"), options);
  chart.render();
}

{
  const colors = [
  {% for cwe in most_common_cwe %}
  '#5C6BC0',
  {% endfor %}
  ];

  const options = {
  series: [{
    name: 'CWE IDs',
    data: [{% for cwe in most_common_cwe %}
      {{cwe.nused}},
      {% endfor %}]
    }],
    chart: {
      height: 350,
      type: 'bar',
      events: {
        click: function(chart, w, e) {
          // console.log(chart, w, e)
        }
      }
    },
    colors: colors,
    plotOptions: {
      bar: {
        columnWidth: '45%',
        distributed: true,
      }
    },
    dataLabels: {
      enabled: false
    },
    legend: {
      show: false
    },
    xaxis: {
      categories: [
        {% for cwe in most_common_cwe %}
        '{{cwe.name}}',
        {% endfor %}
      ],
      labels: {
        style: {
          colors: colors,
          fontSize: '12px'
        }
      }
    }
  };

  const chart = new ApexCharts(document.querySelector("#most_common_cwe"), options);
  chart.render();
}

{
  const colors = [
  {% for tag in most_common_tags %}
  '#EF5350',
  {% endfor %}
  ];

  const options = {
  series: [{
    name: 'Tags',
    data: [{% for tag in most_common_tags %}
      {{tag.nused}},
      {% endfor %}]
    }],
    chart: {
      height: 350,
      type: 'bar',
      events: {
        click: function(chart, w, e) {
          // console.log(chart, w, e)
        }
      }
    },
    colors: colors,
    plotOptions: {
      bar: {
        columnWidth: '45%',
        distributed: true,
      }
    },
    dataLabels: {
      enabled: false
    },
    legend: {
      show: false
    },
    xaxis: {
      categories: [
        {% for tag in most_common_tags %}
        '{{tag.name}}',
        {% endfor %}
      ],
      labels: {
        style: {
          colors: colors,
          fontSize: '12px'
        }
      }
    }
  };

  const chart = new ApexCharts(document.querySelector("#most_common_tags"), options);
  chart.render();
}
