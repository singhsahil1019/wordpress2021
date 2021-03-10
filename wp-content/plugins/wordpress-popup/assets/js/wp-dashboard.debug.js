/* global hustleVars, Chart */
(function ($) {
  'use strict';

  var dashboardWidget = {
    $widget: $('.hustle-widget'),
    activeModuleType: '',
    activeDisplayType: 'total',
    activeTrackingType: 'conversion',
    activeDaysRange: '7',
    trackingData: {},
    totalsData: {},
    daysLabels: [],
    theChart: null,
    init: function init() {
      var _this = this;

      // Handle changing the tracking type and tracking date range.
      this.$widget.find('#hustle-analytics-apply').on('click', function (e) {
        return _this.trackingAndDaysUpdated(e);
      }); // Handle selecting a module type.

      this.$widget.find('.hustle-options-chart .hustle-option').on('click', function (e) {
        return _this.moduleTypeSelected(e);
      }); // Handle selecting a display type.

      this.$widget.find('.hustle-options-embed .hustle-option').on('click', function (e) {
        return _this.displayTypeSelected(e);
      });
      this.setDaysLabels();
      this.setModuleType(this.$widget.find('.hustle-options-chart .hustle-option.hustle-active').data('module-type'));
      this.retrieveData();
    },
    trackingAndDaysUpdated: function trackingAndDaysUpdated(e) {
      e.preventDefault();
      var oldDaysRange = this.activeDaysRange;
      this.activeTrackingType = this.$widget.find('#hustle-analytics-show').val();
      this.activeDaysRange = this.$widget.find('#hustle-analytics-data').val();
      this.setDaysLabels(); // If the days range didn't change, no need to trigger the ajax call.
      // We already have the data for the different display types.

      if (oldDaysRange === this.activeDaysRange) {
        this.buildChart();
        this.updateTotals();
        return;
      }

      this.retrieveData();
    },
    setDaysLabels: function setDaysLabels() {
      var begin = -1 * this.activeDaysRange;
      this.daysLabels = hustleVars.days_labels.slice(begin);
    },
    retrieveData: function retrieveData() {
      var self = this,
          nonce = this.$widget.data('nonce'),
          $noDataMessage = this.$widget.find('.hustle-message-empty'),
          data = {
        _ajax_nonce: nonce,
        action: 'hustle_get_wp_dashboard_widget_data',
        days: this.activeDaysRange,
        trackingType: this.activeTrackingType
      };
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        success: function success(resp) {
          if (resp.success && resp.data) {
            self.trackingData = resp.data.data;
            self.totalsData = resp.data.totals;
            self.buildChart();
            self.updateTotals();
          } else {
            $noDataMessage.show();
          }
        },
        error: function error() {
          $noDataMessage.show();
        }
      });
    },
    moduleTypeSelected: function moduleTypeSelected(e) {
      var $button = $(e.currentTarget),
          moduleType = $button.data('moduleType'),
          success = this.setModuleType(moduleType);

      if (success) {
        // Mark the selected button as selected, and deselect the others.
        this.markButtonAsSelected($button);
        this.buildChart();
      }
    },
    setModuleType: function setModuleType(moduleType) {
      var $displayTypeWrapper = this.$widget.find('.hustle-options-embed'); // Handle the display types for the selected module type.

      if (['slidein', 'popup', 'overall'].includes(moduleType)) {
        // Hide display types.
        $displayTypeWrapper.hide();
      } else if ('social_sharing' === moduleType) {
        // Show display types.
        $displayTypeWrapper.show(); // Social Sharings have 'floating' display types.

        $displayTypeWrapper.find('[data-display-type="floating"]').show();
      } else if ('embedded' === moduleType) {
        // Show display types.
        $displayTypeWrapper.show(); // Embeds don't have 'floating' display types.

        $displayTypeWrapper.find('[data-display-type="floating"]').hide();
      } else {
        // The module type is invalid.
        return false;
      } // Set the active module type.


      this.activeModuleType = moduleType;
      this.buildTrackingActionSelect();
      return true;
    },
    displayTypeSelected: function displayTypeSelected(e) {
      // Only embeds and ssharing modules have display types. Abort if they're not selected.
      if (!['embedded', 'social_sharing'].includes(this.activeModuleType)) {
        return;
      }

      var $button = $(e.currentTarget),
          displayType = $button.data('displayType'); // Only ssharing modules have the 'floating' display type.

      if ('floating' === displayType && 'social_sharing' !== this.activeModuleType) {
        return;
      } // Mark the selected button as selected, and deselect the others.


      this.markButtonAsSelected($button);
      this.activeDisplayType = displayType;
      this.buildChart();
    },
    markButtonAsSelected: function markButtonAsSelected($button) {
      $button.siblings('.hustle-option').removeClass('hustle-active').attr('aria-selected', false);
      $button.addClass('hustle-active').attr('aria-selected', true);
    },
    buildTrackingActionSelect: function buildTrackingActionSelect() {
      var $select = this.$widget.find('#hustle-analytics-show'),
          ssharingFriends = ['popup', 'slidein', 'embedded'],
          isSsharingAlone = !hustleVars.active_module_types.some(function (el) {
        return ssharingFriends.includes(el);
      });
      var html = '';
      var availableActions = Object.assign({}, hustleVars.tracking_actions);

      if ('social_sharing' === this.activeModuleType || isSsharingAlone) {
        delete availableActions.cta_conversion;
        delete availableActions.optin_conversion;

        if ('cta_conversion' === this.activeTrackingType || 'optin_conversion' === this.activeTrackingType) {
          this.activeTrackingType = 'view';
        }
      } // Build the options for the select.


      for (var action in availableActions) {
        var selected = action === this.activeTrackingType ? 'selected' : '';
        html += "<option value=\"".concat(action, "\" ").concat(selected, ">").concat(availableActions[action], "</option>");
      }

      $select.html(html);
    },
    updateTotals: function updateTotals() {
      var totals = this.totalsData,
          getArrowIcon = function getArrowIcon(direction) {
        return "<span class=\"sui-icon-arrow-".concat(direction, " sui-sm\" aria-hidden=\"true\"></span>");
      };

      for (var moduleType in totals) {
        var $button = this.$widget.find(".hustle-options-chart .hustle-option[data-module-type=\"".concat(moduleType, "\"]")),
            $valueHolder = $button.find('.hustle-option--value'),
            $trendHolder = $button.find('.hustle-option--trend'),
            moduleTypeData = totals[moduleType],
            total = moduleTypeData[this.activeTrackingType].total,
            trend = moduleTypeData[this.activeTrackingType].trend;
        var trendHtml = '';
        $trendHolder.removeClass('hustle-up');
        $trendHolder.removeClass('hustle-down');

        if (0 !== trend) {
          if (0 < trend) {
            $trendHolder.addClass('hustle-up');
            trendHtml += getArrowIcon('up');
          } else {
            $trendHolder.addClass('hustle-down');
            trendHtml += getArrowIcon('down');
          }
        }

        $valueHolder.text(total);
        trendHtml += trend + '%';
        $trendHolder.html(trendHtml);
      }
    },
    formatDataForChart: function formatDataForChart() {
      var data = this.trackingData,
          moduleType = this.activeModuleType,
          displayType = this.activeDisplayType,
          trackingType = this.activeTrackingType,
          $noDataMessage = this.$widget.find('.hustle-message-empty');
      var moduleTypeData = {},
          dataToDisplay = {},
          dataKey = moduleType,
          showNoDataMessage = false;

      try {
        if (['popup', 'slidein', 'overall'].includes(moduleType) || 'total' === displayType) {
          moduleTypeData = data[dataKey];
        } else {
          // Social sharing modules are the only with 'floating' display type.
          if ('floating' === displayType && 'social_sharing' !== moduleType) {
            throw false;
          }

          dataKey = moduleType + '_' + displayType;
          moduleTypeData = data[dataKey];
        } // Data for this module type isn't defined. Display the message and abort.


        if ('undefined' === typeof moduleTypeData) {
          throw false;
        }

        showNoDataMessage = 0 === this.totalsData.overall.view.total && 0 === this.totalsData.overall.conversion.total; // There's no data for this module type.

        if (!moduleTypeData || !Object.keys(moduleTypeData).length) {
          throw false;
        } // Get the data for the selected tracking type.


        dataToDisplay = moduleTypeData[trackingType]; // There's no data for this type.

        if ('undefined' === typeof dataToDisplay || !Object.keys(dataToDisplay).length) {
          throw false;
        }

        dataToDisplay = Object.values(dataToDisplay);
      } catch (e) {
        showNoDataMessage = true;
        dataToDisplay = Array(parseInt(this.activeDaysRange)).fill(0);
      } // Display the "we haven't collected enough data yet" message if there's no data.


      if (showNoDataMessage) {
        $noDataMessage.show();
      } else {
        $noDataMessage.hide();
      }

      return dataToDisplay;
    },
    buildChart: function buildChart() {
      var chartData = this.formatDataForChart(),
          datasets = [{
        label: hustleVars.tracking_actions[this.activeTrackingType],
        data: chartData,
        backgroundColor: ['transparent'],
        borderColor: ['#0085BA'],
        borderWidth: 2,
        pointRadius: 0,
        pointHitRadius: 20,
        pointHoverRadius: 4,
        pointHoverBorderColor: '#0085BA',
        pointHoverBackgroundColor: '#FFFFFF'
      }];

      if (this.theChart) {
        this.theChart.destroy();
      }

      this.createNewChart(datasets);
    },
    createNewChart: function createNewChart(datasets) {
      var $chartContainer = this.$widget.find('#hustle-analytics-chart'),
          trackingTypeName = hustleVars.tracking_actions[this.activeTrackingType],
          chartData = {
        labels: this.daysLabels,
        datasets: datasets
      },
          chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        legend: {
          display: false
        },
        scales: {
          yAxes: [{
            gridLines: {
              display: true,
              color: '#F8F8F8',
              zeroLineColor: '#F8F8F8',
              drawBorder: false // Allow zeroLineColor on xAxes.

            },
            ticks: {
              fontColor: '#72777C',
              fontSize: 11
            }
          }],
          xAxes: [{
            gridLines: {
              display: false,
              zeroLineColor: 'rgba(0,0,0,0)',
              drawBorder: false // Allow zeroLineColor on xAxes.

            },
            ticks: {
              fontColor: '#72777C',
              fontSize: 11
            }
          }]
        },
        elements: {
          line: {
            tension: 0
          },
          point: {
            radius: 0.5
          }
        },
        tooltips: {
          xPadding: 12,
          yPadding: 8,
          backgroundColor: '#333333',
          titleFontColor: '#FFFFFF',
          titleFontSize: 15,
          titleFontFamily: 'Roboto',
          titleFontStyle: 'normal',
          titleAlign: 'left',
          titleSpacing: 0,
          titleMarginBottom: 2,
          bodyFontColor: '#AAAAAA',
          bodyFontSize: 11,
          bodyFontFamily: 'Roboto',
          bodyFontStyle: 'normal',
          bodyAlign: 'left',
          cornerRadius: 4,
          displayColors: false,
          callbacks: {
            title: function title(tooltipItem) {
              return tooltipItem[0].yLabel + ' ' + trackingTypeName;
            },
            label: function label(tooltipItem) {
              return tooltipItem.xLabel;
            }
          }
        }
      };
      this.theChart = new Chart($chartContainer[0], {
        type: 'line',
        fill: 'start',
        data: chartData,
        options: chartOptions
      });
    }
  };
  dashboardWidget.init();
})(jQuery);