document.addEventListener('alpine:init', () => {
  // Admin App
  Alpine.data('adminApp', () => ({
    // State
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    overview: { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} },
    ipRotation: { proxies: [], currentIndex: 0 },
    rateLimits: { limits: {} },
    stats: {},
    loginForm: { username: '', password: '' },
    passwordForm: { newPassword: '' },
    ipForm: { proxies: '' },
    newUser: { username: '', password: '', role: 'user', status: 'active' },
    editUserForm: { id: '', username: '', role: '', status: '' },
    selectedUser: null,
    busy: false,
    error: '',
    message: '',
    isReady: false,
    showAddUserModal: false,
    showChangePasswordModal: false,
    showEditUserModal: false,
    activeTab: 'all',
    
    // Computed
    get filteredJobs() {
      if (this.activeTab === 'all') return this.overview.jobs;
      return this.overview.jobs.filter(job => job.status === this.activeTab);
    },
    
    // Methods
    async init() {
      this.isReady = true;
      if (this.token) {
        if (this.user?.role !== 'admin') {
          this.error = 'Current session is not an admin. Please sign in with an admin account.';
          this.logout();
          return;
        }
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
      }
    },
    
    headers() {
      const headers = { 'Content-Type': 'application/json' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      return headers;
    },
    
    async login() {
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Invalid credentials');
        }
        
        const data = await response.json();
        if (data.role !== 'admin') throw new Error('Admin role required');
        
        this.token = data.token;
        this.user = data;
        localStorage.setItem('mailer_token', data.token);
        localStorage.setItem('mailer_user', JSON.stringify(data));
        this.loginForm.password = '';
        
        await this.fetchOverview();
        await this.loadIPRotation();
        await this.loadRateLimits();
        
        this.message = 'Login successful!';
        setTimeout(() => this.message = '', 3000);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async logout() {
      try {
        await fetch('/auth/logout', { method: 'POST', headers: this.headers() });
      } catch (error) {
        console.warn(error);
      }
      this.token = '';
      this.user = null;
      this.overview = { users: [], jobs: [], ipRotation: { proxies: [], currentIndex: 0 }, rateLimits: { limits: {} }, stats: {} };
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
    },
    
    async fetchOverview() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch('/admin/overview', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load admin data');
        const data = await response.json();
        this.overview = data;
        this.stats = data.stats;
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async loadIPRotation() {
      try {
        const response = await fetch('/admin/ip-rotation', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.ipRotation = data;
          this.ipForm.proxies = data.proxies?.join('\n') || '';
        }
      } catch (error) {
        console.error('Failed to load IP rotation:', error);
      }
    },
    
    async loadRateLimits() {
      try {
        const response = await fetch('/admin/rate-limits', { headers: this.headers() });
        if (response.ok) {
          const data = await response.json();
          this.rateLimits = data;
        }
      } catch (error) {
        console.error('Failed to load rate limits:', error);
      }
    },
    
    async updateIPRotation() {
      this.error = '';
      this.busy = true;
      try {
        const proxies = this.ipForm.proxies
          .split('\n')
          .map(p => p.trim())
          .filter(p => p);
        
        const response = await fetch('/admin/ip-rotation', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ proxies })
        });
        
        if (!response.ok) throw new Error('Failed to update IP rotation');
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.loadIPRotation();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async resetAllRateLimits() {
      if (!confirm('Reset all rate limits? This will allow all users to send emails immediately.')) return;
      
      try {
        const response = await fetch('/admin/rate-limits/reset', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({})
        });
        
        if (!response.ok) throw new Error('Failed to reset rate limits');
        
        this.message = 'All rate limits have been reset';
        setTimeout(() => this.message = '', 3000);
        
        await this.loadRateLimits();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async resetUserRateLimit(username) {
      try {
        const response = await fetch('/admin/rate-limits/reset', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ username })
        });
        
        if (!response.ok) throw new Error('Failed to reset rate limit');
        
        this.message = `Rate limit reset for ${username}`;
        setTimeout(() => this.message = '', 3000);
        
        await this.loadRateLimits();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async createUser() {
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch('/admin/users', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.newUser)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to create user');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.showAddUserModal = false;
        this.newUser = { username: '', password: '', role: 'user', status: 'active' };
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    editUser(user) {
      this.editUserForm = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status
      };
      this.showEditUserModal = true;
    },
    
    async updateUser() {
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch(`/admin/users/${this.editUserForm.id}`, {
          method: 'PUT',
          headers: this.headers(),
          body: JSON.stringify(this.editUserForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to update user');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.showEditUserModal = false;
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    showChangePasswordModal(user) {
      this.selectedUser = user;
      this.passwordForm.newPassword = '';
      this.showChangePasswordModal = true;
    },
    
    async changeUserPassword() {
      if (!this.passwordForm.newPassword) {
        this.error = 'Please enter a new password';
        return;
      }
      
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch(`/admin/users/${this.selectedUser.id}/change-password`, {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ newPassword: this.passwordForm.newPassword })
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to change password');
        }
        
        const data = await response.json();
        this.message = data.message;
        this.showChangePasswordModal = false;
        this.passwordForm.newPassword = '';
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async deleteUser(userId) {
      if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
      
      try {
        const response = await fetch(`/admin/users/${userId}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete user');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async sendJob(jobId) {
      if (!confirm('Send this email job now?')) return;
      
      try {
        const response = await fetch(`/api/jobs/${jobId}/send`, {
          method: 'POST',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to send job');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async deleteJob(jobId) {
      if (!confirm('Delete this job?')) return;
      
      try {
        const response = await fetch(`/api/jobs/${jobId}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete job');
        }
        
        const data = await response.json();
        this.message = data.message;
        setTimeout(() => this.message = '', 3000);
        
        await this.fetchOverview();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    formatDate(value) {
      if (!value) return '—';
      try {
        return new Date(value).toLocaleString();
      } catch (error) {
        return value;
      }
    },
    
    redirectHome() {
      window.location.href = '/index.html';
    },
    
    openUserPanel() {
      window.location.href = '/user.html';
    }
  }));

  // User App
  Alpine.data('dashboardApp', () => ({
    // State
    token: localStorage.getItem('mailer_token') || '',
    user: JSON.parse(localStorage.getItem('mailer_user') || 'null'),
    jobs: [],
    busy: false,
    message: '',
    error: '',
    loginForm: { username: '', password: '' },
    form: {
      subject: '',
      recipients: '',
      textBody: '',
      htmlBody: '',
      smtpUsername: '',
      smtpPassword: ''
    },
    
    // Computed
    get isAdmin() {
      return this.user?.role === 'admin';
    },
    
    // Methods
    async init() {
      if (this.token) {
        await this.fetchJobs();
        await this.refreshProfile();
      }
    },
    
    headers() {
      const headers = { 'Content-Type': 'application/json' };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;
      return headers;
    },
    
    async login() {
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Invalid credentials');
        }
        
        const data = await response.json();
        
        // Check if user is suspended
        if (data.status === 'suspended') {
          throw new Error('Your account has been suspended. Please contact an administrator.');
        }
        
        this.token = data.token;
        this.user = { 
          username: data.username, 
          role: data.role, 
          mailboxes: data.mailboxes || [],
          status: data.status 
        };
        
        localStorage.setItem('mailer_token', this.token);
        localStorage.setItem('mailer_user', JSON.stringify(this.user));
        this.loginForm.password = '';
        
        await this.fetchJobs();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async logout() {
      if (this.token) {
        try {
          await fetch('/auth/logout', { method: 'POST', headers: this.headers() });
        } catch (error) {
          console.warn(error);
        }
      }
      localStorage.removeItem('mailer_token');
      localStorage.removeItem('mailer_user');
      this.token = '';
      this.user = null;
      this.jobs = [];
    },
    
    async refreshProfile() {
      if (!this.token) return;
      try {
        const response = await fetch('/auth/me', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to fetch profile');
        const data = await response.json();
        this.user = data;
        localStorage.setItem('mailer_user', JSON.stringify(data));
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async fetchJobs() {
      if (!this.token) return;
      this.error = '';
      this.busy = true;
      try {
        const response = await fetch('/api/jobs', { headers: this.headers() });
        if (!response.ok) throw new Error('Unable to load jobs');
        this.jobs = await response.json();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async createJob() {
      this.error = '';
      this.message = '';
      
      // Validate required fields
      if (!this.form.subject || !this.form.recipients || !this.form.smtpUsername || !this.form.smtpPassword) {
        this.error = 'All required fields must be filled.';
        return;
      }
      
      this.busy = true;
      try {
        const response = await fetch('/api/jobs', {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify(this.form)
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to create job');
        }
        
        const data = await response.json();
        
        // Clear form
        Object.keys(this.form).forEach((key) => (this.form[key] = ''));
        this.message = 'Job created successfully!';
        
        setTimeout(() => {
          this.message = '';
        }, 4000);
        
        // Refresh data
        await Promise.all([this.fetchJobs(), this.refreshProfile()]);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.busy = false;
      }
    },
    
    async triggerSend(id) {
      if (!confirm('Send this email job now?')) return;
      
      try {
        const response = await fetch(`/api/jobs/${id}/send`, {
          method: 'POST',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to send job');
        }
        
        const data = await response.json();
        this.message = data.message;
        
        setTimeout(() => {
          this.message = '';
        }, 4000);
        
        await this.fetchJobs();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    async deleteJob(id) {
      if (!confirm('Delete this job?')) return;
      
      try {
        const response = await fetch(`/api/jobs/${id}`, {
          method: 'DELETE',
          headers: this.headers()
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.message || 'Failed to delete job');
        }
        
        const data = await response.json();
        this.message = data.message;
        
        setTimeout(() => {
          this.message = '';
        }, 4000);
        
        await this.fetchJobs();
      } catch (error) {
        this.error = error.message;
      }
    },
    
    formatDate(value) {
      if (!value) return '—';
      try {
        return new Date(value).toLocaleString();
      } catch (error) {
        return value;
      }
    },
    
    openAdmin() {
      window.location.href = '/admin.html';
    }
  }));
});